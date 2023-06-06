import requests

from conftest import url


class TestRequests:

    @staticmethod
    def get_request(endpoint):
        response = requests.get(f"{url}"+f"{endpoint}")
        return response

    @staticmethod
    def post_request(endpoint, request_body):
        response = requests.post(f"{url}" + f"{endpoint}", data=request_body)
        print(response)
        return response

    @staticmethod
    def put_request(endpoint, request_body, headers):
        response = requests.put(f"{url}" + f"{endpoint}", data=request_body, headers=headers)
        return response

    @staticmethod
    def patch_request(endpoint, request_body, headers):
        response = requests.patch(f"{url}" + f"{endpoint}", data=request_body, headers=headers)
        return response

    @staticmethod
    def delete_request(endpoint, headers):
        response = requests.delete(f"{url}" + f"{endpoint}", headers=headers)
        return response

    @staticmethod
    def get_request_with_headers(endpoint, headers):
        response = requests.get(f"{url}" + f"{endpoint}", headers=headers)
        return response

    @staticmethod
    def post_request_with_headers(endpoint, request_body, headers):
        response = requests.post(f"{url}" + f"{endpoint}", request_body, headers=headers)
        return response

    @staticmethod
    def get_request_with_params(endpoint, params, headers):
        response = requests.get(f"{url}" + f"{endpoint}", params=params, headers=headers)
        return response

    @staticmethod
    def patch_request_with_params(endpoint, request_body, params, headers):
        response = requests.patch(f"{url}" + f"{endpoint}", request_body, params=params, headers=headers)
        return response
