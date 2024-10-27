import logging
from superset.security import SupersetSecurityManager


class CustomSsoSecurityManager(SupersetSecurityManager):
    def oauth_user_info(self, provider, response=None):
        logging.debug("Oauth2 provider: {0}.".format(provider))
        if provider == "awscognito":
            # Construct the user info URL
            user_info_url = (
                f"https://antonytest.auth.us-east-1.amazoncognito.com/oauth2/userInfo"
            )
            logging.debug("User info URL: {0}".format(user_info_url))

            # Assuming you're using Flask-OAuthlib or similar
            oauth_remote = self.appbuilder.sm.oauth_remotes[provider]
            user_info_response = oauth_remote.get(user_info_url)

            logging.debug("User info response: {0}".format(user_info_response))

            if user_info_response.status_code == 200:
                me = user_info_response.json()
                logging.debug("user_data: {0}".format(me))
                return {
                    "name": me.get("name", ""),
                    "email": me.get("email", ""),
                    "id": me.get("sub", ""),
                    "username": me.get("username", ""),
                    "first_name": me.get("given_name", ""),
                    "last_name": me.get("family_name", ""),
                }
            else:
                logging.error(
                    "Failed to get user info: {0} - {1}".format(
                        user_info_response.status_code, user_info_response.text
                    )
                )
                return None
