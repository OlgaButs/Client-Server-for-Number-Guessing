import pytest
import socket
from server import new_client

# Socket for Testing Purposes:
testingSocket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
testingSocket.bind(("127.0.0.1",1235))
#testingSocket.connect(("127.0.0.1",1234))

result = new_client(testingSocket,{ "op" : "START", "client_id" : "IMaTEST" })

assert isinstance(result, dict)
assert "op" in result
assert "status" in result

assert result["status"] == True
assert result["op"] == "START"

print("Everything's working alright!")