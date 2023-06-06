Download the project from the GitHub repository
Repo link - **"https://github.com/karthikcharank-deloitte/Pytest_API_Main_Assignment.git"**
(or)
Clone the project using the command,
**git clone "https://github.com/karthikcharank-deloitte/Pytest_API_Main_Assignment.git"**

After setting up project,

From Terminal, give the following command to install the libraries
Command - **pip install requirements.txt**
which will install all the necessary packages for the project.

To run the testcases enter the command in the terminal:
**pytest tests**

Command to run Sanity Testcases: 
**pytest -m Sanity tests** 

Command to run Regression Testcases: 
**pytest -m Regression tests **

To generate allure reports install the following packages in cmd and verify Java and Node are present,
1. Install allure-pytest package 
Command - **pip install allure-pytest**
2. Install Java8+ and install node.js
3. Install allure command line tool
Command - **npm install -g allure-commandline --save-dev**

Commands to generate JSON formatted report,
**cd tests
pytest --alluredir <Path of Reports folder from Root directory>**
Note: Create a folder named Reports in the project directory

Command to convert JSON Report to HTML Report,
From cmd enter the following command:
**allure serve <Path of Reports folder from Root directory>**

