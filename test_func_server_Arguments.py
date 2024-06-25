import pytest
#import os
from subprocess import Popen
from subprocess import PIPE

# os.chdir('..')
# print(os.getcwd())

def test_insufficient_arguments():
    result = Popen("python server.py", stdout=PIPE, shell=True)
    assert result.wait() == 1 # Check return code.
    assert "Usage -> python server.py SERVER_PORT" in result.stdout.read().decode("utf-8")

def test_invalid_port():
    result = Popen("python server.py not_number", stdout= PIPE, shell= True)
    assert result.wait() == 1 # verificate return code
    assert "Invalid PORT Number! Must be within [1,65534]. Closing the program..." in result.stdout.read().decode("utf-8")

def test_optional_arguments():
    result = Popen("python server.py client_id  8080  localhost  ooo", stdout= PIPE, shell= True)
    assert result.wait() == 1 # verificate return code
    assert "Usage -> python server.py SERVER_PORT" in result.stdout.read().decode("utf-8")

test_insufficient_arguments()
test_invalid_port()
test_optional_arguments()
print("Everything went fine!")