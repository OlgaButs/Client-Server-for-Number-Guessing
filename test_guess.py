import pytest
import socket
from server import new_client, guess_client, number_client, stop_client


# Socket for Testing Purposes:
testingSocket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
testingSocket.bind(("127.0.0.1",1235))
#testingSocket.connect(("127.0.0.1",1234))

result = new_client(testingSocket,{ "op" : "START", "client_id" : "IMaTEST" }) # Method needed for guess_client to work.

number = number_client(testingSocket,{ "op" : "NUMBER", "number" : 23 }) # Method needed for guess_client to work.
stop  = stop_client(testingSocket,{ "op" : "STOP" })
result = guess_client(testingSocket,{ "op": "GUESS", "choice": "min" })

assert isinstance(result, dict)
assert "op" in result
assert "status" in result

assert result["status"] == True
assert result["op"] == "GUESS"