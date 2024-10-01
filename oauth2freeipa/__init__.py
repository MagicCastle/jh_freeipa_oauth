import shlex
import subprocess

from jupyterhub.auth import LocalAuthenticator

from traitlets import Bool, Dict, Unicode, Union, default, observe

class LocalFreeIPAAuthenticator(LocalAuthenticator):
    """Authenticator that add system user to FreeIPA database"""

    default_group = Unicode("def-sponsor00",
        config=True,
        help="",
    )
    keytab_path = Unicode("/etc/jupyterhub/jupyterhub.keytab",
        config=True,
        help="",
    )
    keytab_principal = Unicode("jupyterhub",
        config=True,
        help="",
    )
    user_add_cmd = Unicode("ipa_create_user.py",
        config=True,
        help="",
    )
    def add_system_user(self, user):
        subprocess.run(["kinit", "-kt", self.keytab_path, "-p", self.keytab_principal])
        user_add_cmd = shlex.split(user_add_cmd) + [user.name]
        if self.default_group:
            user_add_cmd.extend(["--posix_group", self.default_group])
        subprocess.run(user_add_cmd)
        subprocess.run(["kdestroy", "-p", self.keytab_principal])

