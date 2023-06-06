import pytest

from requests_file import TestRequests
from data import Data


class TestRegisterAndLogin(Data):

    @pytest.mark.Sanity
    def test_health_check(self):  # GET request
        log = Data.getLogger(self)
        log.info("Testing API: /health-check")
        log.info("Request Type: GET")
        response = TestRequests.get_request("/health-check")
        response_body = response.json()
        print(response_body)
        assert response.status_code == 200
        log.info("Status code verified as 200")
        assert response_body["success"] == True
        assert response_body["message"] == "Notes API is Running"
        log.info("Response body verified")

    @pytest.mark.Sanity
    def test_register(self):  # POST request
        log = Data.getLogger(self)
        log.info("Testing API: /users/register")
        log.info("Request Type: POST")
        response = TestRequests.post_request("/users/register", Data.register_data)
        log.info("New user registered successfully..!!")
        response_body = response.json()
        assert response.status_code == 201
        log.info("Response code verified as 201")
        print(response_body)

    @pytest.mark.Regression
    def test_register_with_same_data(self):  # POST request
        log = Data.getLogger(self)
        log.info("Testing API: /users/register")
        log.info("Request Type: POST")
        response = TestRequests.post_request("/users/register", Data.register_data)
        log.warn("Registration failed..!!")
        response_body = response.json()
        assert response.status_code == 409
        log.info("Response code verified as 409")
        print(response_body)

    @pytest.mark.Regression
    def test_register_with_invalid_data(self):  # POST request
        log = Data.getLogger(self)
        log.info("Testing API: /users/register")
        log.info("Request Type: POST")
        response = TestRequests.post_request("/users/register", Data.register_invalid_data)
        log.warning("Registration failed..!!")
        response_body = response.json()
        assert response.status_code == 400
        log.info("Response code verified as 400")
        print(response_body)

    @pytest.mark.Sanity
    def test_login(self):  # POST request
        log = Data.getLogger(self)
        log.info("Testing API: /users/login")
        log.info("Request Type: POST")
        response = TestRequests.post_request("/users/login", Data.login_data)
        log.info("Login successful..!!")
        response_body = response.json()
        assert response.status_code == 200
        log.info("Response code verified as 200")
        print(response_body)

    @pytest.mark.Regression
    def test_login_with_invalid_data(self):  # POST request
        log = Data.getLogger(self)
        log.info("Testing API: /users/login")
        log.info("Request Type: POST")
        response = TestRequests.post_request("/users/login", Data.login_invalid_data)
        log.warning("Login Failed..!!")
        response_body = response.json()
        assert response.status_code == 401
        log.info("Response code verified as 401")
        print(response_body)

    @pytest.mark.Sanity
    def test_profile_info(self):  # GET request
        log = Data.getLogger(self)
        log.info("Testing API: /users/profile")
        log.info("Request Type: GET")
        response = TestRequests.post_request("/users/login", Data.login_data)
        response_body = response.json()
        print(response_body["data"]["token"])
        log.info("Token: " + response_body["data"]["token"])
        auth_token = response_body["data"]["token"]
        headers = {'x-auth-token': auth_token, 'Content-type': 'application/json'}
        response = TestRequests.get_request_with_headers("/users/profile", headers)
        log.info("Profile data retrieved successfully..!!")
        response_body = response.json()
        print(response_body)
        assert response.status_code == 200
        log.info("Response code verified as 200")

    @pytest.mark.Regression
    def test_profile_info_without_token(self):  # GET request
        log = Data.getLogger(self)
        log.info("Testing API: /users/profile")
        log.info("Request Type: GET")
        response = TestRequests.post_request("/users/login", Data.login_data)
        response_body = response.json()
        response = TestRequests.get_request("/users/profile")
        log.critical("Unauthorized Request..!!")
        response_body = response.json()
        print(response_body)
        assert response.status_code == 401
        log.info("Response code verified as 401")

    @pytest.mark.Sanity
    def test_update_profile(self):  # PATCH request
        log = Data.getLogger(self)
        log.info("Testing API: /users/profile")
        log.info("Request Type: PATCH")
        response = TestRequests.post_request("/users/login", Data.login_data)
        response_body = response.json()
        print(response_body["data"]["token"])
        auth_token = response_body["data"]["token"]
        log.info("Authentication Token: " + auth_token)
        headers = {'x-auth-token': auth_token}
        response = TestRequests.patch_request("/users/profile", Data.profile_data, headers)
        log.info("Profile updated successfully..!!")
        response_body = response.json()
        print(response_body)
        assert response.status_code == 200
        log.info("Response code verified as 200")

    @pytest.mark.Sanity
    def test_update_profile_without_token(self):  # PATCH request
        log = Data.getLogger(self)
        log.info("Testing API: /users/profile")
        log.info("Request Type: PATCH")
        response = TestRequests.post_request("/users/login", Data.login_data)
        response_body = response.json()
        headers = {'x-auth-token': ""}
        response = TestRequests.patch_request("/users/profile", Data.profile_data, headers)
        log.critical("Unauthorized Request..!!")
        response_body = response.json()
        print(response_body)
        assert response.status_code == 401
        log.info("Response code verified as 401")

    @pytest.mark.Sanity
    def test_forgot_password(self):  # POST request
        log = Data.getLogger(self)
        log.info("Testing API: /users/forgot-password")
        log.info("Request Type: POST")
        response = TestRequests.post_request("/users/forgot-password", Data.email)
        log.info("Password reset email sent successfully..!!")
        response_body = response.json()
        print(response_body)
        assert response.status_code == 200
        log.info("Response code verified as 200")

    @pytest.mark.Sanity
    def test_forgot_password_with_invalid_email(self):  # POST request
        log = Data.getLogger(self)
        log.info("Testing API: /users/forgot-password")
        log.info("Request Type: POST")
        response = TestRequests.post_request("/users/forgot-password", "abcd")
        log.warning("Invalid Email..!!")
        response_body = response.json()
        print(response_body)
        assert response.status_code == 400
        log.info("Response code verified as 400")

    @pytest.mark.Sanity
    def test_verify_invalid_token(self):  # POST request
        log = Data.getLogger(self)
        log.info("Testing API: /users/verify-reset-password-token")
        log.info("Request Type: POST")
        response = TestRequests.post_request("/users/verify-reset-password-token", "82426add806a4a839d7786b08c858371a90d9207b2eb42c3ab669c423b9140ff")
        log.warning("The provided password reset token is invalid or has expired..!!")
        assert response.status_code == 401
        log.info("Response code verified as 401")

    @pytest.mark.Sanity
    def test_reset_password(self):  # POST request
        log = Data.getLogger(self)
        log.info("Testing API: /users/reset-password")
        log.info("Request Type: POST")
        response = TestRequests.post_request("/users/reset-password", Data.reset_password)
        log.info("Password reset successful..!!")
        response_body = response.json()
        print(response_body)

    @pytest.mark.Regression
    def test_reset_password_with_invalid_data(self):  # POST request
        log = Data.getLogger(self)
        log.info("Testing API: /users/reset-password")
        log.info("Request Type: POST")
        response = TestRequests.post_request("/users/reset-password", Data.reset_password)
        log.warning("Invalid token passed..!!")
        response_body = response.json()
        print(response_body)
        assert response.status_code == 401
        log.info("Response code is verified as 401")

    @pytest.mark.Sanity
    def test_change_password(self):  # POST request
        log = Data.getLogger(self)
        log.info("Testing API: /users/change-password")
        log.info("Request Type: POST")
        response = TestRequests.post_request("/users/login", Data.login_data)
        response_body = response.json()
        print(response_body)
        print(response_body["data"]["token"])
        auth_token = response_body["data"]["token"]
        log.info("Authentication Token: " + auth_token)
        headers = {'x-auth-token': auth_token}
        response = TestRequests.post_request_with_headers("/users/change-password", Data.change_password, headers)
        log.info("Password changed successfully..!!")
        response_body = response.json()
        print(response_body)
        assert response.status_code == 200
        log.info("Response code verified as 200")

    @pytest.mark.Sanity
    def test_logout(self):
        log = Data.getLogger(self)
        log.info("Testing API: /users/logout")
        log.info("Request Type: POST")
        response = TestRequests.post_request("/users/login", Data.new_login_data)
        response_body = response.json()
        print(response_body)
        auth_token = response_body["data"]["token"]
        headers = {'x-auth-token': auth_token}
        response = TestRequests.delete_request("/users/logout", headers)
        response_body = response.json()
        log.info("User logged out successfully..!!")
        print(response_body)
        assert response.status_code == 200
        log.info("Response code verified as 200")

    @pytest.mark.Regression
    def test_logout_without_token(self):
        log = Data.getLogger(self)
        log.info("Testing API: /users/logout")
        log.info("Request Type: POST")
        response = TestRequests.post_request("/users/login", Data.new_login_data)
        headers = {'x-auth-token': ""}
        response = TestRequests.delete_request("/users/logout", headers)
        response_body = response.json()
        log.info("Logout failed..!!")
        print(response_body)
        assert response.status_code == 401
        log.info("Response code verified as 401")

    @pytest.mark.Sanity
    def test_delete_account(self):
        log = Data.getLogger(self)
        log.info("Testing API: /users/delete-account")
        log.info("Request Type: DELETE")
        response = TestRequests.post_request("/users/login", Data.new_login_data)
        response_body = response.json()
        print(response_body)
        auth_token = response_body["data"]["token"]
        headers = {'x-auth-token': auth_token}
        response = TestRequests.delete_request("/users/delete-account", headers)
        response_body = response.json()
        log.info("User account deleted successfully..!!")
        print(response_body)
        assert response.status_code == 200
        log.info("Response code verified as 200")

    @pytest.mark.Regression
    def test_delete_account_without_token(self):
        log = Data.getLogger(self)
        log.info("Testing API: /users/delete-account")
        log.info("Request Type: DELETE")
        response = TestRequests.post_request("/users/login", Data.new_login_data)
        headers = {'x-auth-token': ""}
        response = TestRequests.delete_request("/users/delete-account", headers)
        response_body = response.json()
        log.info("User account deletion failed..!!")
        print(response_body)
        assert response.status_code == 401
        log.info("Response code verified as 401")
