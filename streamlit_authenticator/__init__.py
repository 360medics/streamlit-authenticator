import streamlit as st
import yaml
from authenticate import Authenticate
from yaml.loader import SafeLoader

_RELEASE = True

if _RELEASE:
    # Loading config file
    with open("config.yaml") as file:
        config = yaml.load(file, Loader=SafeLoader)

    # Creating the authenticator object
    authenticator = Authenticate(
        config["credentials"],
        config["cookie"]["name"],
        config["cookie"]["key"],
        config["cookie"]["expiry_days"],
        config["preauthorized"],
    )

    # creating a login widget
    authenticator.login()
    if st.session_state["authentication_status"]:
        authenticator.logout()
        st.write(f'Bonjour *{st.session_state["name"]}*')
        st.title("Un super contenu")
    elif st.session_state["authentication_status"] is False:
        st.error("La combinaistion nom d'utilisateur et mot de passe est incorecte")
    elif st.session_state["authentication_status"] is None:
        st.warning(
            "Merci de saisir votre nom d’utilisateur ainsi que votre mot de passe."
        )

    # Creating a password reset widget
    if st.session_state["authentication_status"]:
        try:
            if authenticator.reset_password(
                st.session_state["username"],
            ):
                st.success("Votre mot de passe a été mis à jours")
        except Exception as e:
            st.error(e)

    # Creating a new user registration widget
    try:
        if authenticator.register_user("S'inscrire", preauthorization=False):
            st.success("L'utilisateur a été enregistré avec succès.")
    except Exception as e:
        st.error(e)

    # Creating a forgot password widget
    try:
        (
            username_forgot_pw,
            email_forgot_password,
            random_password,
        ) = authenticator.forgot_password("Mot de passe oublié")
        if username_forgot_pw:
            st.success("New password sent securely")
            # Random password to be transferred to user securely
        else:
            st.error("Username not found")
    except Exception as e:
        st.error(e)

    # Creating a forgot username widget
    try:
        (
            username_forgot_username,
            email_forgot_username,
        ) = authenticator.forgot_username()
        if username_forgot_username:
            st.success("Username sent securely")
            # Username to be transferred to user securely
        else:
            st.error("Email not found")
    except Exception as e:
        st.error(e)

    # Creating an update user details widget
    if st.session_state["authentication_status"]:
        try:
            if authenticator.update_user_details(
                st.session_state["username"], "Update user details"
            ):
                st.success("Entries updated successfully")
        except Exception as e:
            st.error(e)

    # Saving config file
    with open("config.yaml", "w") as file:
        yaml.dump(config, file, default_flow_style=False)
