import inspect
import logging


class Data:

    register_data = {
        "name": "ABCD",
        "email": "acb8167@gmail.com",
        "password": "abc@123"
    }

    register_invalid_data = {
        "name": "ABCD",
        "email": "acb8167",
        "password": "abc@123"
    }

    login_data = {
        "email": "acb8167@gmail.com",
        "password": "abc@123"
    }

    login_invalid_data = {
        "email": "acb8167@gmail.com",
        "password": "hbsdhbv"
    }
    profile_data = {
        "name": "Practice User",
        "phone": "9876543210",
        "company": "Expand Testing"
    }

    email = {"email": "karthikcharan994@gmail.com"}

    reset_password = {
        "token": "82426add806a4a839d7786b08c858371a90d9207b2eb42c3ab669c423b9140ff",
        "newPassword": "abcd@1234"
    }

    invalid_reset_password = {
        "token": "abcd",
        "newPassword": "abc@1234"
    }

    new_login_data = {
        "email": "acb8167@gmail.com",
        "password": "abcd@12345"
    }

    change_password = {
        "currentPassword": "abc@123",
        "newPassword": "abcd@12345"
    }

    notes_login_data = {
        "email": "acb8163@gmail.com",
        "password": "abc@123"
    }

    notes_data = {
        "title": "Note4",
        "description": "Sample Personal Note",
        "category": "Personal"
    }

    invalid_notes_data = {
        "title": 1234,
        "description": 12345,
        "category": "School"
    }

    updated_notes_data = {
        "id": "6478debb62a54902112cc795",
        "title": "Note1",
        "description": "Home note updated",
        "completed": "false",
        "category": "Home"
    }

    note_status_data = {
        "id": "6478debb62a54902112cc795",
        "completed": "true"
    }

    def getLogger(self):
        loggerName = inspect.stack()[1][3]
        logger = logging.getLogger(loggerName)
        fileHandler = logging.FileHandler("C:/Users/karthikck/PycharmProjects/Pytest_API_Main_Assignment/Logs/logfile.log")
        formatter = logging.Formatter("%(asctime)s :%(levelname)s : %(name)s :%(message)s")
        fileHandler.setFormatter(formatter)
        logger.handlers = []
        logger.addHandler(fileHandler)
        logger.setLevel(logging.DEBUG)
        return logger
