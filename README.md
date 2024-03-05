# Idea book
**Web app to store trip ideas and manage users.**
## Table of Contents

- [About the Project](#about-the-project)
- [Used Python Modules](#used-python-modules)
- [Usage](#usage)
- [Requirements](#requirements)


## About the Project
A **Python3** program for collecting information about computer (for the project this will be one machine) **hardware**, **operating systems**, installed **software** and their versions.

App consists of two elements: a **client** part that will provide information about a given machine and the **server** part which stores the data.

Information is stored in .db file database using **SQLite3** module in Python.
Data about system, software and hardware of clients is visible only for administrator in the web interface.

GUI was designed using **Django** framework.

While the program is executing, we can watch the communication between the client and the server in the console.

Communication between the client and the server is **encrypted** to maintain security.

## Used Python Modules

Program was developed with those **Python modules**:
- **socket**
- **psutil**
- **winreg**
- **platform**
- **os**
- **django**

## Usage
App can be used in order to verify whether there is any software on the computers particularly susceptible to exposure.

## Requirements

- Python 3
- IDE for Python
- Django Framework





