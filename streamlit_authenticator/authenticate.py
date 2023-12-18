from datetime import datetime, timedelta

import bcrypt
import extra_streamlit_components as stx
import jwt
import streamlit as st
from exceptions import (
    CredentialsError,
    ForgotError,
    RegisterError,
    ResetError,
    UpdateError,
)
from hasher import Hasher
from loguru import logger
from utils import generate_random_pw
from validator import Validator


class Authenticate:
    """
    This class will create login, logout, register user,
    reset password, forgot password,
    forgot username, and modify user details widgets.
    """

    def __init__(
        self,
        credentials: dict,
        cookie_name: str,
        key: str,
        cookie_expiry_days: float = 30.0,
        preauthorized: list = None,
        validator: Validator = None,
    ):
        """
        Create a new instance of "Authenticate".

        Parameters
        ----------
        credentials: dict
            The dictionary of usernames, names, passwords, and emails.
        cookie_name: str
            The name of the JWT cookie stored on the client's browser for
            passwordless reauthentication.
        key: str
            The key to be used for hashing the signature of the JWT cookie.
        cookie_expiry_days: float
            The number of days before the cookie expires on the client's
            browser.
        preauthorized: list
            The list of emails of unregistered users authorized to register.
        validator: Validator
            A Validator object that checks the validity of the username,
            name, and email fields.
        """
        self.credentials = credentials
        self.credentials["usernames"] = {
            key.lower(): value for key, value in credentials["usernames"].items()
        }
        self.cookie_name = cookie_name
        self.key = key
        self.cookie_expiry_days = cookie_expiry_days
        self.preauthorized = preauthorized
        self.cookie_manager = stx.CookieManager()
        self.validator = validator if validator is not None else Validator()

        if "name" not in st.session_state:
            st.session_state["name"] = None
        if "authentication_status" not in st.session_state:
            st.session_state["authentication_status"] = None
        if "username" not in st.session_state:
            st.session_state["username"] = None
        if "logout" not in st.session_state:
            st.session_state["logout"] = None

    def _token_encode(self) -> str:
        """
        Encodes the contents of the reauthentication cookie.

        Returns
        -------
        str
            The JWT cookie for passwordless reauthentication.
        """
        return jwt.encode(
            {
                "name": st.session_state["name"],
                "username": st.session_state["username"],
                "exp_date": self.exp_date,
            },
            self.key,
            algorithm="HS256",
        )

    def _token_decode(self) -> str:
        """
        Decodes the contents of the reauthentication cookie.

        Returns
        -------
        str
            The decoded JWT cookie for passwordless reauthentication.
        """
        try:
            return jwt.decode(self.token, self.key, algorithms=["HS256"])
        except Exception as e:
            logger.debug(e)
            return False

    def _set_exp_date(self) -> str:
        """
        Creates the reauthentication cookie's expiry date.

        Returns
        -------
        str
            The JWT cookie's expiry timestamp in Unix epoch.
        """
        return (datetime.utcnow() + timedelta(days=self.cookie_expiry_days)).timestamp()

    def _check_pw(self) -> bool:
        """
        Checks the validity of the entered password.

        Returns
        -------
        bool
            The validity of the entered password by comparing
            it to the hashed password on disk.
        """
        return bcrypt.checkpw(
            self.password.encode(),
            self.credentials["usernames"][self.username]["password"].encode(),
        )

    def _check_cookie(self):
        """
        Checks the validity of the reauthentication cookie.
        """
        self.token = self.cookie_manager.get(self.cookie_name)
        if self.token is not None:
            self.token = self._token_decode()
            if self.token is not False:
                if not st.session_state["logout"]:
                    if self.token["exp_date"] > datetime.utcnow().timestamp():
                        if "name" and "username" in self.token:
                            st.session_state["name"] = self.token["name"]
                            st.session_state["username"] = self.token["username"]
                            st.session_state["authentication_status"] = True

    def _check_credentials(
        self,
        inplace: bool = True,
    ) -> bool:
        """
        Checks the validity of the entered credentials.

        Parameters
        ----------
        inplace: bool
            Inplace setting,
            True: authentication status will be stored in session state,
            False: authentication status will be returned as bool.
        Returns
        -------
        bool
            Validity of entered credentials.
        """
        if self.username in self.credentials["usernames"]:
            try:
                if self._check_pw():
                    if inplace:
                        st.session_state["name"] = self.credentials["usernames"][
                            self.username
                        ]["name"]
                        self.exp_date = self._set_exp_date()
                        self.token = self._token_encode()
                        self.cookie_manager.set(
                            self.cookie_name,
                            self.token,
                            expires_at=datetime.now()
                            + timedelta(days=self.cookie_expiry_days),
                        )
                        st.session_state["authentication_status"] = True
                    else:
                        return True
                else:
                    if inplace:
                        st.session_state["authentication_status"] = False
                    else:
                        return False
            except Exception as e:
                print(e)
        else:
            if inplace:
                st.session_state["authentication_status"] = False
            else:
                return False

    def login(
        self,
        form_name: str = "Connexion",
        location: str = "main",
    ) -> tuple:
        """
        Creates a login widget.

        Parameters
        ----------
        form_name: str
            The rendered name of the login form.
        location: str
            The location of the login form i.e. main or sidebar.
        Returns
        -------
        str
            Name of the authenticated user.
        bool
            The status of authentication, None: no credentials entered,
            False: incorrect credentials, True: correct credentials.
        str
            Username of the authenticated user.
        """
        if location not in ["main", "sidebar"]:
            raise ValueError("Location must be one of 'main' or 'sidebar'")
        if not st.session_state["authentication_status"]:
            self._check_cookie()
            if not st.session_state["authentication_status"]:
                if location == "main":
                    login_form = st.form("Connexion")
                elif location == "sidebar":
                    login_form = st.sidebar.form("Connexion")

                login_form.subheader(form_name)
                login_form.markdown(
                    "*Pour vous connecter, vous devez avoir créé un compte, et faire partie des utilisateurs autorisés.*"
                )
                self.username = login_form.text_input("Nom d'utilisateur")
                st.session_state["username"] = self.username
                self.password = login_form.text_input("Mot de passe", type="password")

                login_form.markdown(
                    "Mot de passe/nom d'utilisateur oublié ? Complétez ce [formulaire](https://airtable.com/appW74yfcakhYbgsa/pag6Qvjdt8rlQRfx2/form)",
                    unsafe_allow_html=True,
                )

                if login_form.form_submit_button("Se connecter"):
                    self._check_credentials()

        return (
            st.session_state["name"],
            st.session_state["authentication_status"],
            st.session_state["username"],
        )

    def logout(
        self,
        button_name: str = "Déconnexion",
        location: str = "main",
        key: str = None,
    ):
        """
        Creates a logout button.

        Parameters
        ----------
        button_name: str
            The rendered name of the logout button.
        location: str
            The location of the logout button i.e. main or sidebar.
        """
        if location not in ["main", "sidebar"]:
            raise ValueError("Location must be one of 'main' or 'sidebar'")
        if location == "main":
            if st.button(button_name, key):
                self.cookie_manager.delete(self.cookie_name)
                st.session_state["logout"] = True
                st.session_state["name"] = None
                st.session_state["username"] = None
                st.session_state["authentication_status"] = None
        elif location == "sidebar":
            if st.sidebar.button(button_name, key):
                self.cookie_manager.delete(self.cookie_name)
                st.session_state["logout"] = True
                st.session_state["name"] = None
                st.session_state["username"] = None
                st.session_state["authentication_status"] = None

    def _update_password(
        self,
        username: str,
        password: str,
    ):
        """
        Updates credentials dictionary with user's reset hashed password.

        Parameters
        ----------
        username: str
            The username of the user to update the password for.
        password: str
            The updated plain text password.
        """
        self.credentials["usernames"][username]["password"] = Hasher(
            [password]
        ).generate()[0]

    def reset_password(
        self,
        username: str,
        form_name: str = "Réinitialiser votre mot de passe",
        location: str = "main",
    ) -> bool:
        """
        Creates a password reset widget.

        Parameters
        ----------
        username: str
            The username of the user to reset the password for.
        form_name: str
            The rendered name of the password reset form.
        location: str
            The location of the password reset form i.e. main or sidebar.
        Returns
        -------
        str
            The status of resetting the password.
        """
        if location not in ["main", "sidebar"]:
            raise ValueError("Location must be one of 'main' or 'sidebar'")
        if location == "main":
            reset_password_form = st.form("Réinitialiser votre mot de passe")
        elif location == "sidebar":
            reset_password_form = st.sidebar.form("Réinitialiser votre mot de passe")

        reset_password_form.subheader(form_name)
        self.username = username.lower()
        self.password = reset_password_form.text_input(
            "Ancien mot de passe", type="password"
        )
        new_password = reset_password_form.text_input(
            "Nouveau mot de passe", type="password"
        )
        new_password_repeat = reset_password_form.text_input(
            "Répétez votre nouveau mot de passe", type="password"
        )

        if reset_password_form.form_submit_button("Réinitialiser"):
            if self._check_credentials(inplace=False):
                if len(new_password) > 0:
                    if new_password == new_password_repeat:
                        if self.password != new_password:
                            self._update_password(self.username, new_password)
                            return True
                        else:
                            raise ResetError(
                                "Le nouveau et l'ancien mot de passe sont identiques"
                            )
                    else:
                        raise ResetError(
                            "Le nouveau et l'ancien mot de passe ne sont pas identiques"
                        )
                else:
                    raise ResetError("Vous n'avez pas fourni de nouveau mot de passe")
            else:
                raise CredentialsError("Mot de passe")

    def _register_credentials(
        self,
        username: str,
        name: str,
        password: str,
        email: str,
        preauthorization: bool,
    ):
        """
        Adds to credentials dictionary the new user's information.

        Parameters
        ----------
        username: str
            The username of the new user.
        name: str
            The name of the new user.
        password: str
            The password of the new user.
        email: str
            The email of the new user.
        preauthorization: bool
            The preauthorization requirement,
            True: user must be preauthorized to register,
            False: any user can register.
        """
        if not self.validator.validate_username(username):
            raise RegisterError("Username is not valid")
        if not self.validator.validate_name(name):
            raise RegisterError("Name is not valid")
        if not self.validator.validate_email(email):
            raise RegisterError("Email is not valid")

        self.credentials["usernames"][username] = {
            "name": name,
            "password": Hasher([password]).generate()[0],
            "email": email,
        }
        if preauthorization:
            self.preauthorized["emails"].remove(email)

    def register_user(
        self,
        form_name: str = "S'inscrire",
        location: str = "main",
        preauthorization=True,
    ) -> bool:
        """
        Creates a register new user widget.

        Parameters
        ----------
        form_name: str
            The rendered name of the register new user form.
        location: str
            The location of the register new user form i.e. main or sidebar.
        preauthorization: bool
            The preauthorization requirement,
            True: user must be preauthorized to register,
            False: any user can register.
        Returns
        -------
        bool
            The status of registering the new user, True: user registered successfully.
        """
        if preauthorization:
            if not self.preauthorized:
                raise ValueError("preauthorization argument must not be None")
        if location not in ["main", "sidebar"]:
            raise ValueError("Location must be one of 'main' or 'sidebar'")
        if location == "main":
            register_user_form = st.form("S'inscrire")
        elif location == "sidebar":
            register_user_form = st.sidebar.form("S'inscrire")

        register_user_form.subheader(form_name)
        new_email = register_user_form.text_input(
            "Email, utilisé pour l'inscription sur la liste d'attente"
        )
        new_username = register_user_form.text_input(
            "Nom d'utilisateur, il vous servira pour vous connecter"
        )
        new_name = register_user_form.text_input("Prénom Nom")
        new_password = register_user_form.text_input("Mot de passe", type="password")
        new_password_repeat = register_user_form.text_input(
            "Confirmer le mot de passe", type="password"
        )
        cgu_accepted = register_user_form.checkbox(
            "J'ai lu et j'accepte les [conditions générales d'utilisation](https://pulselife.com/fr-fr/legal/conditions-generales-d-utilisation).",
        )

        if register_user_form.form_submit_button("S'inscrire"):
            if cgu_accepted:
                if (
                    len(new_email)
                    and len(new_username)
                    and len(new_name)
                    and len(new_password) > 0
                ):
                    if new_username not in self.credentials["usernames"]:
                        if new_password == new_password_repeat:
                            if preauthorization:
                                if new_email in self.preauthorized["emails"]:
                                    self._register_credentials(
                                        new_username,
                                        new_name,
                                        new_password,
                                        new_email,
                                        preauthorization,
                                    )
                                    return True
                                else:
                                    raise RegisterError(
                                        "L'utilisateur n'est pas préautorisé à s'inscrire."
                                    )
                            else:
                                self._register_credentials(
                                    new_username,
                                    new_name,
                                    new_password,
                                    new_email,
                                    preauthorization,
                                )
                                return True
                        else:
                            raise RegisterError(
                                "Les mots de passe ne correspondent pas."
                            )
                    else:
                        raise RegisterError("Nom d’utilisateur déjà utilisé")
                else:
                    raise RegisterError(
                        "Veuillez entrer une adresse e-mail, un nom d'utilisateur, un nom et un mot de passe."
                    )
            else:
                raise RegisterError(
                    "Veuillez accepter les conditions générale d'utilisation"
                )

    def _set_random_password(self, username: str) -> str:
        """
        Updates credentials dictionary with user's hashed random password.

        Parameters
        ----------
        username: str
            Username of user to set random password for.
        Returns
        -------
        str
            New plain text password that should be transferred to user securely.
        """
        self.random_password = generate_random_pw()
        self.credentials["usernames"][username]["password"] = Hasher(
            [self.random_password]
        ).generate()[0]
        return self.random_password

    def forgot_password(
        self,
        form_name: str = "Mot de passe oublié",
        location: str = "main",
    ) -> tuple:
        """
        Creates a forgot password widget.

        Parameters
        ----------
        form_name: str
            The rendered name of the forgot password form.
        location: str
            The location of the forgot password form i.e. main or sidebar.
        Returns
        -------
        str
            Username associated with forgotten password.
        str
            Email associated with forgotten password.
        str
            New plain text password that should be transferred to user securely.
        """
        if location not in ["main", "sidebar"]:
            raise ValueError("Location must be one of 'main' or 'sidebar'")
        if location == "main":
            forgot_password_form = st.form("Mot de passe oublié")
        elif location == "sidebar":
            forgot_password_form = st.sidebar.form("Mot de passe oublié")

        forgot_password_form.subheader(form_name)
        username = forgot_password_form.text_input("Nom d'utilisateur").lower()

        if forgot_password_form.form_submit_button("Soumettre"):
            if len(username) > 0:
                if username in self.credentials["usernames"]:
                    return (
                        username,
                        self.credentials["usernames"][username]["email"],
                        self._set_random_password(username),
                    )
                else:
                    return False, None, None
            else:
                raise ForgotError("Nom d'utilisateur non fourni.")
        return None, None, None

    def _get_username(self, key: str, value: str) -> str:
        """
        Retrieves username based on a provided entry.

        Parameters
        ----------
        key: str
            Name of the credential to query i.e. "email".
        value: str
            Value of the queried credential i.e. "jsmith@gmail.com".
        Returns
        -------
        str
            Username associated with given key, value pair i.e. "jsmith".
        """
        for username, entries in self.credentials["usernames"].items():
            if entries[key] == value:
                return username
        return False

    def forgot_username(
        self,
        form_name: str = "Nom d'utilisateur oublié",
        location: str = "main",
    ) -> tuple:
        """
        Creates a forgot username widget.

        Parameters
        ----------
        form_name: str
            The rendered name of the forgot username form.
        location: str
            The location of the forgot username form i.e. main or sidebar.
        Returns
        -------
        str
            Forgotten username that should be transferred to user securely.
        str
            Email associated with forgotten username.
        """
        if location not in ["main", "sidebar"]:
            raise ValueError("Location must be one of 'main' or 'sidebar'")
        if location == "main":
            forgot_username_form = st.form("Nom d'utilisateur oublié")
        elif location == "sidebar":
            forgot_username_form = st.sidebar.form("Nom d'utilisateur oublié")

        forgot_username_form.subheader(form_name)
        email = forgot_username_form.text_input("Email")

        if forgot_username_form.form_submit_button("Soumettre"):
            if len(email) > 0:
                return self._get_username("email", email), email
            else:
                raise ForgotError("Email non fourni")
        return None, email

    def _update_entry(self, username: str, key: str, value: str):
        """
        Updates credentials dictionary with user's updated entry.

        Parameters
        ----------
        username: str
            The username of the user to update the entry for.
        key: str
            The updated entry key i.e. "email".
        value: str
            The updated entry value i.e. "jsmith@gmail.com".
        """
        self.credentials["usernames"][username][key] = value

    def update_user_details(
        self,
        username: str,
        form_name: str = "Mettre à jour les détails de l'utilisateur.",
        location: str = "main",
    ) -> bool:
        """
        Creates a update user details widget.

        Parameters
        ----------
        username: str
            The username of the user to update user details for.
        form_name: str
            The rendered name of the update user details form.
        location: str
            The location of the update user details form i.e. main or sidebar.
        Returns
        -------
        str
            The status of updating user details.
        """
        if location not in ["main", "sidebar"]:
            raise ValueError("Location must be one of 'main' or 'sidebar'")
        if location == "main":
            update_user_details_form = st.form(
                "Mettre à jour les détails de l'utilisateur."
            )
        elif location == "sidebar":
            update_user_details_form = st.sidebar.form(
                "Mettre à jour les détails de l'utilisateur."
            )

        update_user_details_form.subheader(form_name)
        self.username = username.lower()
        field = update_user_details_form.selectbox(
            "Champ", ["Nom d'utilisateur", "Email"]
        )
        new_value = update_user_details_form.text_input("Nouvelle valeur")

        if update_user_details_form.form_submit_button("Mettre à jour"):
            if len(new_value) > 0:
                if new_value != self.credentials["usernames"][self.username][field]:
                    self._update_entry(self.username, field, new_value)
                    if field == "name":
                        st.session_state["name"] = new_value
                        self.exp_date = self._set_exp_date()
                        self.token = self._token_encode()
                        self.cookie_manager.set(
                            self.cookie_name,
                            self.token,
                            expires_at=datetime.now()
                            + timedelta(days=self.cookie_expiry_days),
                        )
                    return True
                else:
                    raise UpdateError(
                        "Les nouvelles valeurs et les valeurs actuelles sont identiques."
                    )
            if len(new_value) == 0:
                raise UpdateError("Nouvelle valeur non fournie.")
