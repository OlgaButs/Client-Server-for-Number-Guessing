import pytest
#import os
from subprocess import Popen
from subprocess import PIPE
#from threading import Thread

# os.chdir('..')
# print(os.getcwd())

def test_insufficient_arguments():
    result = Popen("python client.py", stdout=PIPE, stdin=PIPE, shell=True)
    assert result.wait() == 1 # Check return code.
    assert "Usage -> python client.py CLIENT_NAME SERVER_PORT SERVER_IP" in result.stdout.read().decode("utf-8")

def test_invalid_port():
    result = Popen("python client.py client_id  not_number", stdout=PIPE, stdin=PIPE, shell=True)
    assert result.wait() == 1 # verificate return code
    assert "Invalid PORT number! Must be within [1,65534]." in result.stdout.read().decode("utf-8")

def test_invalid_ip():
    result = Popen("python client.py client_id  8080  3333", stdout=PIPE, stdin=PIPE, shell=True)
    assert result.wait() == 1 # verificate return code
    assert "Invalid IPv4!" in result.stdout.read().decode("utf-8")

def test_optional_arguments():
    result = Popen("python client.py client_id  8080  localhost  ooo", stdout=PIPE, stdin=PIPE, shell=True)
    assert result.wait() == 1 # verificate return code
    assert "Usage -> python client.py CLIENT_NAME SERVER_PORT SERVER_IP" in result.stdout.read().decode("utf-8")


test_insufficient_arguments()
test_invalid_ip()
test_invalid_port()
test_optional_arguments()
print("Everything went fine!")