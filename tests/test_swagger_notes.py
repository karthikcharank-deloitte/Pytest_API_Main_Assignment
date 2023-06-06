import pytest
from requests_file import TestRequests
from data import Data


class TestNotes(Data):

    @pytest.mark.Sanity
    def test_create_note(self):
        log = Data.getLogger(self)
        log.info("Testing API: /notes")
        log.info("Request Type: POST")
        response = TestRequests.post_request("/users/login", Data.notes_login_data)
        log.info("Login successful..!!")
        response_body = response.json()
        print(response_body)
        print(response_body["data"]["token"])
        auth_token = response_body["data"]["token"]
        log.info("Token: " + auth_token)
        headers = {'x-auth-token': auth_token}
        response = TestRequests.post_request_with_headers("/notes", Data.notes_data, headers)
        log.info("Note created successfully..!!")
        response_body = response.json()
        print(response_body)
        assert response.status_code == 200
        log.info("Response code verified as 200")

    @pytest.mark.Regression
    def test_create_note_with_invalid_dta(self):
        log = Data.getLogger(self)
        log.info("Testing API: /notes")
        log.info("Request Type: POST")
        response = TestRequests.post_request("/users/login", Data.notes_login_data)
        log.info("Login successful..!!")
        response_body = response.json()
        print(response_body)
        print(response_body["data"]["token"])
        auth_token = response_body["data"]["token"]
        log.info("Token: " + auth_token)
        headers = {'x-auth-token': auth_token}
        response = TestRequests.post_request_with_headers("/notes", Data.invalid_notes_data, headers)
        log.info("Invalid category selected..!!")
        response_body = response.json()
        print(response_body)
        assert response.status_code == 400
        log.info("Response code verified as 400")

    @pytest.mark.Sanity
    def test_get_all_notes(self):
        log = Data.getLogger(self)
        log.info("Testing API: /notes")
        log.info("Request Type: GET")
        response = TestRequests.post_request("/users/login", Data.notes_login_data)
        response_body = response.json()
        print(response_body)
        print(response_body["data"]["token"])
        auth_token = response_body["data"]["token"]
        headers = {'x-auth-token': auth_token}
        response = TestRequests.get_request_with_headers("/notes", headers)
        log.info("All Notes retrieved successfully..!!")
        response_body = response.json()
        print(response_body)
        assert response.status_code == 200
        log.info("Response code verified as 200")

    @pytest.mark.Regression
    def test_get_all_notes_without_token(self):
        log = Data.getLogger(self)
        log.info("Testing API: /notes")
        log.info("Request Type: GET")
        response = TestRequests.post_request("/users/login", Data.notes_login_data)
        headers = {'x-auth-token': ""}
        response = TestRequests.get_request_with_headers("/notes", headers)
        log.info("Unauthorized Request..!!")
        response_body = response.json()
        print(response_body)
        assert response.status_code == 401
        log.info("Response code verified as 401")

    @pytest.mark.Sanity
    @pytest.mark.parametrize("note_id", ["6478debb62a54902112cc795"])
    def test_get_notes_by_id(self, note_id):
        log = Data.getLogger(self)
        log.info("Testing API: /notes/{id}")
        log.info("Request Type: GET")
        response = TestRequests.post_request("/users/login", Data.notes_login_data)
        response_body = response.json()
        print(response_body)
        print(response_body["data"]["token"])
        auth_token = response_body["data"]["token"]
        log.info("Authentication Token: " + auth_token)
        headers = {'x-auth-token': auth_token}
        params = {"note_id": note_id}
        response = TestRequests.get_request_with_params(f"/notes/{note_id}", params, headers)
        log.info("Note successfully retrieved by ID")
        response_body = response.json()
        print(response_body)
        assert response.status_code == 200
        log.info("Response code verified as 200")

    @pytest.mark.Regression
    @pytest.mark.parametrize("note_id", ["abcd"])
    def test_get_notes_by_invalid_id(self, note_id):
        log = Data.getLogger(self)
        log.info("Testing API: /notes/{id}")
        log.info("Request Type: GET")
        response = TestRequests.post_request("/users/login", Data.notes_login_data)
        response_body = response.json()
        print(response_body)
        auth_token = response_body["data"]["token"]
        log.info("Authentication Token: " + auth_token)
        headers = {'x-auth-token': auth_token}
        params = {"note_id": note_id}
        response = TestRequests.get_request_with_params(f"/notes/{note_id}", params, headers)
        log.info("Invalid note ID is passed..!!")
        response_body = response.json()
        print(response_body)
        assert response.status_code == 400
        log.info("Response code verified as 400")

    @pytest.mark.Sanity
    def test_update_notes(self):
        log = Data.getLogger(self)
        log.info("Testing API: /notes/{id}")
        log.info("Request Type: POST")
        response = TestRequests.post_request("/users/login", Data.notes_login_data)
        response_body = response.json()
        print(response_body)
        print(response_body["data"]["token"])
        auth_token = response_body["data"]["token"]
        headers = {'x-auth-token': auth_token}
        response = TestRequests.get_request_with_headers("/notes", headers)
        response_body = response.json()
        note_id = response_body["data"][0]["id"]
        response = TestRequests.put_request(f"/notes/{note_id}", Data.updated_notes_data, headers)
        log.info("Note updated successfully..!!")
        response_body = response.json()
        print(response_body)
        assert response.status_code == 200
        log.info("Response code verified as 200")

    @pytest.mark.Regression
    def test_update_notes_without_token(self):
        log = Data.getLogger(self)
        log.info("Testing API: /notes/{id}")
        log.info("Request Type: POST")
        response = TestRequests.post_request("/users/login", Data.notes_login_data)
        headers = {'x-auth-token': ""}
        response = TestRequests.get_request_with_headers("/notes", headers)
        note_id = "6478debb62a54902112cc795"
        response = TestRequests.put_request(f"/notes/{note_id}", Data.updated_notes_data, headers)
        log.info("Unauthorized Request..!!")
        response_body = response.json()
        print(response_body)
        assert response.status_code == 401
        log.info("Response code verified as 401")

    @pytest.mark.Sanity
    @pytest.mark.parametrize("note_id", ["6478debb62a54902112cc795"])
    def test_update_note_status(self, note_id):  # PATCH request
        log = Data.getLogger(self)
        log.info("Testing API: /notes/{id}")
        log.info("Request Type: PATCH")
        response = TestRequests.post_request("/users/login", Data.notes_login_data)
        response_body = response.json()
        print(response_body["data"]["token"])
        auth_token = response_body["data"]["token"]
        log.info("Authentication Token: " + auth_token)
        headers = {'x-auth-token': auth_token}
        response = TestRequests.patch_request(f"/notes/{note_id}", Data.note_status_data, headers)
        log.info("Note updated successfully..!!")
        response_body = response.json()
        print(response_body)
        assert response.status_code == 200
        log.info("Response code verified as 200")

    @pytest.mark.Regression
    @pytest.mark.parametrize("note_id", ["6479acc918bd080211d07cd1"])
    def test_delete_note(self, note_id):  # DELETE request
        log = Data.getLogger(self)
        log.info("Testing API: /notes/{id}")
        log.info("Request Type: DELETE")
        response = TestRequests.post_request("/users/login", Data.notes_login_data)
        response_body = response.json()
        print(response_body["data"]["token"])
        auth_token = response_body["data"]["token"]
        log.info("Authentication Token: " + auth_token)
        headers = {'x-auth-token': auth_token}
        response = TestRequests.delete_request(f"/notes/{note_id}", headers)
        log.info("Note deleted successfully..!!")
        response_body = response.json()
        print(response_body)
        log.info("Response code verified as 200")

    @pytest.mark.Regression
    @pytest.mark.parametrize("note_id", ["abcd"])
    def test_delete_note_with_invalid_id(self, note_id):  # DELETE request
        log = Data.getLogger(self)
        log.info("Testing API: /notes/{id}")
        log.info("Request Type: DELETE")
        response = TestRequests.post_request("/users/login", Data.notes_login_data)
        response_body = response.json()
        print(response_body["data"]["token"])
        auth_token = response_body["data"]["token"]
        log.info("Authentication Token: " + auth_token)
        headers = {'x-auth-token': auth_token}
        response = TestRequests.delete_request(f"/notes/{note_id}", headers)
        log.info("Invalid note ID is passed..!!")
        response_body = response.json()
        print(response_body)
        assert response.status_code == 400
        log.info("Response code verified as 400")

