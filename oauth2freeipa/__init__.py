import shlex
import subprocess
import time

from jupyterhub.auth import LocalAuthenticator

from oauthenticator.generic import GenericOAuthenticator
from oauthenticator.github import GitHubOAuthenticator
from oauthenticator.cilogon import CILogonOAuthenticator

from traitlets import Unicode, Int


class LocalFreeIPAAuthenticator(LocalAuthenticator):
    """Authenticator that add system user to FreeIPA database"""

    max_add_user_retry = Int(10, config=True, help="")

    default_group = Unicode(
        "def-sponsor00",
        config=True,
        help="",
    )
    keytab_path = Unicode(
        "/etc/jupyterhub/jupyterhub.keytab",
        config=True,
        help="",
    )
    keytab_principal = Unicode(
        "jupyterhub",
        config=True,
        help="",
    )
    user_add_cmd = Unicode(
        "ipa_create_user.py",
        config=True,
        help="",
    )

    def system_user_exists(self, user):
        subprocess.run(
            ["kinit", "-kt", self.keytab_path, "-p", self.keytab_principal],
            capture_output=True,
        )
        process = subprocess.run(["ipa", "user-show", user.name], capture_output=True)
        subprocess.run(["kdestroy", "-p", self.keytab_principal], capture_output=True)
        if process.returncode == 0:
            return True
        else:
            return False

    def add_system_user(self, user):
        user_add_cmd = shlex.split(self.user_add_cmd) + [user.name]
        if self.default_group:
            user_add_cmd.extend(["--posix_group", self.default_group])

        try:
            subprocess.run(
                ["kinit", "-kt", self.keytab_path, "-p", self.keytab_principal],
                capture_output=True
            )
        except:
            raise RuntimeError(
                f"Failed to create FreeIPA user {user.name} - could not init Kerberos"
            )

        try:
            subprocess.run(user_add_cmd, capture_output=True)
        except:
            raise RuntimeError(
                f"Failed to create FreeIPA user {user.name} - fail to run {user_add_cmd}"
            )

        try:
            subprocess.run(["kdestroy", "-p", self.keytab_principal], capture_output=True)
        except:
            raise RuntimeError(
                f"Failed to create FreeIPA user {user.name} - fail to destroy Kerberos ticket"
            )

        for i in range(self.max_add_user_retry):
            if not self.system_user_exists(user):
                time.sleep(1)
            else:
                return

        raise RuntimeError(
            f"Failed to create FreeIPA user {user.name} - user cannot be found after {self.max_add_user_retry} retries."
        )


class LocalFreeIPAGenericOAuthenticator(
    LocalFreeIPAAuthenticator, GenericOAuthenticator
):
    """Mixes FreeIPA user creation and generic OAuthenticator"""


class LocalFreeIPAGitHubOAuthenticator(LocalFreeIPAAuthenticator, GitHubOAuthenticator):
    """Mixes FreeIPA user creation and GitHub OAuthenticator"""


class LocalFreeIPACILogonOAuthenticator(
    LocalFreeIPAAuthenticator, CILogonOAuthenticator
):
    """Mixes FreeIPA user creation and GitHub OAuthenticator"""
