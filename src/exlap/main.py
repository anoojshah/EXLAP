#!/opt/homebrew/bin/python3
import sys

sys.path.append(".")
import argparse
import asyncio
import base64
import hashlib
import random
import aiofiles
import re

import exlap_cmds as cmd
import exlap_v2 as api
from datetime import datetime
import streams
import xml.etree.ElementTree as ET
from xml.etree.ElementTree import ParseError



# --Global--
# Because VAG starts at 99
session_number = 98
nonce = ""
user = "PHP-D22200" #creds.user
#user = "Test_TB-105000"
#password = "s4T2K6BAv0a7LQvrv3vdaUl17xEl2WJOpTmAThpRZe0=="
password = "Gv2g7nOS9DN1bkQA9YFDttZ1QqNeUDzg/2rzrnEKH70=" #creds.password
carIP = "10.173.189.1"  #IP of car
authd = None
# netcat debug flag
debug_127 = 0
outputFile = 'exlap.txt'  #default file if user does not provide one
outputXML = True  #default is true
data = []
# --/Global--


# TODO - we may be able to remove this entirely. Not needed
def make_nonce(length=16):
    """Generate pseudo-random number.
    this function isn't required but was useful during testing"""
    a = "".join([str(random.randint(0, 255)) for i in range(length)])
    return a.encode("utf-8")


def make_cnonce():
    """seeds a cnonce, returned as a 16 int byte arrary-> base64 encoded-> and
    converted to a str
    """
    b_cnonce = bytearray(16)
    for i in range(16):
        b_cnonce[i] = random.randint(0, 255)
        cnonce = (base64.b64encode(b_cnonce)).decode("utf-8")
    return cnonce

# TODO - include or kill?
def calculate_digest_v2(user: str, password: str, nonce: bytes, cnonce: bytes):
    """
    this is a MD5 calculation function for authentication. Not tested or
    likely working. MD5 may be implimented in other model cars, but appears to
    default to sha256 in late model Porsche
    """
    digest = hashlib.md5()
    digest.update((user + ":" + password).encode())
    digest2 = hashlib.md5()
    # digest2.update((byte_array_to_hex_string(nonce) + ":" + byte_array_to_hex_string(cnonce)).encode())
    digest2.update((nonce.hex() + ":" + cnonce.hex()).encode())
    digest3 = hashlib.md5()
    # digest3.update((byte_array_to_hex_string(digest.digest()) + ":" + byte_array_to_hex_string(digest2.digest())).encode())
    digest3.update(((digest.digest().hex()) + ":" + (digest2.digest().hex())).encode())
    return digest3.digest()


def Req_Auth_Challenge():
    """
    Step 1 of 2, exlap server authentication
    
    <Req id="100">
    <Authenticate phase="challenge" useHash="sha256"/>
    </Req>
    """
    message = api.Req()
    cmd.conn_count()
    message.set_id(session_number)
    auth = api.Authenticate()
    auth.set_phase(api.phaseType.CHALLENGE)
    auth.set_useHash("sha256")
    # TODO improve XML schema for sha256 support, ie. auth.set_useHash('sha256')
    message.set_Authenticate(auth)
    return str(message)


def Req_Auth_Response(nonce):
    """
    Step 2 of 2, exlap server authentication

    using nonce_worker(), parses response xml msg from server for nonce content.
    nonce_worker passes nonce value to exlap_sha256_64() and creates a sha256
    digest.

    <Req id="101">
        <Authenticate phase="response" cnonce="1Y9BZPOYQyfBMQrqM/cDaA=="
        digest="BBk5/Y2EVXJW1oRQ+Kan0iN/nZTGnHtVGles9a8zCTQ=" user="foobar"/>
    </Req>

    """
    message = api.Req()
    cmd.conn_count()
    message.set_id(session_number)
    auth = api.Authenticate()
    auth.set_phase(api.phaseType.RESPONSE)
    cnonce = make_cnonce()
    auth.set_cnonce(cnonce)
    digest = exlap_sha256_as_b64(user, password, nonce, cnonce)
    auth.set_digest(digest)
    auth.set_user(user)
    print('sending username')
    message.set_Authenticate(auth)
    return str(message)

async def parseDatObject(queue):
    
    outputString=""
    name = ""
    val = ""

    datBlob = await queue.get()
    print("parseDatObject: received data blog", datBlob)
    timestamp = datBlob.get('timeStamp')
    url = datBlob.get('url')

    #reformat timestamp to show minute:second.microseconds
    timestamp = timestamp[:-6] #remove the timezone offset as it messes up parsing
    t1 = datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%S.%f")
    formatted_time = f"{t1.minute:02d}:{t1.second:02d}.{t1.microsecond:06d}"

    #handle special cases such as (i) multiple values for espTyreVelocities, (ii) <Rel> instead of <Abs> for some commands
    if url == 'espTyreVelocities' or url == 'Nav_GeoPosition':
    #    print('timestamp:', formatted_time, ' found ', url)
        abs_tags = datBlob.findall('Abs')
        for abs_tag in abs_tags:
            name = url + '_' + abs_tag.get('name')
            val = abs_tag.get('val')
            outputString = outputString + formatted_time + "," + name + "," + val + "\n"
        
    elif url.startswith('rel') or url.startswith('chassis') or url.startswith('acceleratorPosition'):
        rel_tag = datBlob.find('Rel')
        name = rel_tag.get('name')
        val = rel_tag.get('val')                
    else:
    #    print('timestamp: ', timestamp, ' url: ', url, 'abs: ', dat.find('Abs').get('name'), 'val: ',dat.find('Abs').get('val') )
        abs_tag = datBlob.find('Abs')
        name = abs_tag.get('name')
        val = abs_tag.get('val')       

    outputString = formatted_time + "," + name + "," + val + "\n"
    await write_to_file(outputFile,outputString)


async def nonce_worker(data):
    """
    Reads msgs on AsyncTCPClient() recieve socket. Parse for challenge nonce.
    Sets nonce AND authd global variables.
    """
    global nonce, authd
    if nonce == "":
        try:
            doc = ET.XML(data.decode())
            memoryElem = doc.find("Challenge")
            nonce = memoryElem.get("nonce")
            authd = True
            print('autd set to true')
        except Exception as e:
            print(
                f"EXLAP Server response does not include Challenge - {e}\nResponse: {doc}"
            )
        pass
    else:
        pass


def exlap_sha256_as_b64(user: str, password: str, nonce: bytes, cnonce: bytes):
    """sha256digest and additional hashing steps required for EXLAP auth as implimented. 
    This method is not complient with v1.3 EXLAP documentation from 2017.
    """
    digest = hashlib.sha256()
    digest.update((user + ":" + password + ":" + nonce + ":" + cnonce).encode("utf-8"))
    base64encoded = base64.b64encode(digest.digest()).decode("utf-8")
    return base64encoded

async def write_to_file(filename: str, content: str) -> None:
    async with aiofiles.open(filename, "a") as f:
        await f.write(content)


class AsyncTCPClient:
    """
    Asyncio socket connection. Creates three methods connect, send and receive.

    "await self.writer.drain()" waits for completion of msg transmission.

    "await self.reader.readuntil([b"</Rsp>", b"</Req>", b"</Dat>", b"</Status>"]"
    is patched streams.py from asyncio. It chunks data based on lines ending in 
    exlap message tags. patch* https://github.com/python/cpython/pull/16429
    """

    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.reader = None
        self.writer = None

    async def connect(self):
        # calling our patched asyncio streams class
        self.reader, self.writer = await streams.open_connection(self.host, self.port)
        print("connect(): connection opened" )

    async def send(self, message):
        self.writer.write(message.encode("utf8"))
        await self.writer.drain()
        print(f"\nSent: {message}\n")
        #await write_to_file(outputFile,message)

    async def receive(self, dataQueue):
        """parses recieved messages from tcp socket. Looks for exlap xml tags,
        </Rsp>, </Req>, </Dat>, or </Status>.
        """
        print("in receive()")
        
        data = await self.reader.readuntil(
            [b"</Rsp>", b"</Req>", b"</Dat>", b"</Status>"]
        )
        print(f"\nReceived: {data.decode('utf8')}\n")

        if nonce == "":
            try:
                print("RECEIVE: waiting for nonce_worker()")
                await nonce_worker(data)
            except:
                print("nonce challenge not found - unauthenticated or still looking")
        
        # if we got vehicle signals, put it in the queue for processing
        if "<Dat" in data.decode('utf-8'):
            print("received vehicle data signals: ", data.decode('utf-8'))
            pattern = r'<Dat>(.*?)</Dat>'
            dats = re.findall(pattern,data.decode('utf-8'))  #data blob can have multiple XMl structures so parse each one
            for a_dat in dats:
                print("Receive(): found a <Dat>: ", a_dat)
                datBlob = ET.fromstring(a_dat)
                await dataQueue.put(datBlob)

        '''
        if "<Dat" in data.decode('utf-8'):
            print("received vehicle data signals: ", data.decode('utf-8'))
            tree = ET.parse(data.decode('utf-8'))
            for datBlob in tree.findall('.//Dat'):
                outputString = parseDatObject(datBlob)
                print("DEBUG: processed output ", outputString)
            await write_to_file(outputFile,outputString)
'''
        
        

        

    async def close(self):
        self.writer.close()
        await self.writer.wait_closed()


async def main():

    #define command line arguments & read them
    parser = argparse.ArgumentParser(description="EXLAP Telemetry - Connects to a VW Group vehicle and reads vehicle data to a csv file")
    parser.add_argument("outputfile", help="output file name")
    
    args = parser.parse_args()
    outputFile = args.outputfile
    print("outfile file: ", outputFile)


    # try to connect to car
    if debug_127 == 0:
        print('trying to connect to car at IP: ', carIP)
        client = AsyncTCPClient(carIP, 25010)
    else:
        print('debug networking mode')
        client = AsyncTCPClient("127.0.0.1", 8888)
    await client.connect()

    #create queue for sending commands to the car
    exlap_queue = asyncio.Queue()

    #create queue to process data from the car
    processSignals = asyncio.Queue()
    
    # Exlap Authentication
    async def exlap_auth_worker():
        """worker submits exlap auth commands to server
        TODO - this can be made much more robust"""
        global authd, nonce
        while not authd:
            print('Starting auth process')
            # Read initial server response
            await client.receive(processSignals)
            # Send auth challenge
            await client.send(Req_Auth_Challenge())
            await asyncio.sleep(2)
            # Read response
            await client.receive(processSignals)
            print('waiting for connection...<auth_worker>')
        await client.send(Req_Auth_Response(nonce))
        print('Connected! <auth_worker>')

    await exlap_auth_worker()
    # /Exlap Authentication

    exlap_commands = [
        #cmd.Req_Dir('*'),
        #cmd.Sub_vehicleIdenticationNumber(),
        cmd.Sub_Car_vehicleInformation(),
        cmd.Sub_lateralAcceleration(),
        cmd.Sub_espTyreVelocities(),
        cmd.Sub_vehicleSpeed(),
        cmd.Sub_longitudinalAcceleration(),
        cmd.Sub_wheelAngle(),
        #cmd.Sub_currentOutputPower(),
        cmd.Sub_torqueDistribution(),
        cmd.Sub_acceleratorPosition(),
        cmd.Sub_gearboxOilTemperature(),
        cmd.Sub_yawRate(),
        cmd.Sub_brakePressure(),
        cmd.Sub_Nav_GeoPosition(),
        cmd.Sub_torqueDistribution(),
      #  cmd.Sub_currentOutputPower(),
      #  cmd.Sub_temperatureRearLeft(),
      #  cmd.Sub_temperatureRearRight(),
      #  cmd.Sub_allWheelDriveTorque(),
        cmd.Sub_relAllWheelDriveTorque(),
        #cmd.Sub_currentOutputPower(),
        #cmd.Sub_powermeter(),
        cmd.Sub_suspensionProfile(),
        cmd.Sub_suspensionStates(),
        cmd.Sub_chassisUndersteering(),
        cmd.Sub_chassisOversteering(),
        cmd.Sub_temperatureRearLeft(),
        ]
    for cmds in exlap_commands:
        print("sending commands to car for data subscription")
        await exlap_queue.put(cmds)


    async def exlap_worker(name, exlap_queue):
        """worker submits exlap commands to server"""
        print('exlap worker check in')
        while True:
            # Get a "work item" out of the queue.
            task = await exlap_queue.get()
            # Work on the task
            print(task)
            await client.send(task)
            # Notify the queue that the "work item" has been processed.
            exlap_queue.task_done()
            # print(f'exlap_worker submitted: \n{task}')



    tasks = []
    for i in range(1):
        task = asyncio.create_task(exlap_worker(f"exlap_worker-{i}", exlap_queue))
        tasks.append(task)

        await exlap_queue.join()

    async def heartbeat():
        """sends a hearbeat command to exlap server every 2 sec."""
        while client and authd:
            await asyncio.sleep(2)
            await client.send(cmd.Req_heartbeat())
        else:  
            await task.cancel()

    asyncio.create_task(heartbeat())


     
    # TODO - Worker functions:
    # - ingest the bootstrap exlap command list
    # - Insert the commands into the main() loop to be sent
    # - read the command, set a heart beat timer into the queue if its a subscription
    # - set a timer function to see how long tasks are taking to be completed
    # - og subscriptions somewhere

    # TODO - Need a way to assign the worker function to process the queue
    # Method to create workers for a given queue. tasks[] used for worker management
    #     # Wait until the queue is fully processed.

    # TODO - need a way to clean/monitor/manage the workers
    #     # Cancel our worker tasks.
    #     for task in tasks:
    #         task.cancel()
    #     # Wait until all worker tasks are cancelled.


    # #TODO - test out whether this logic is necessary and working

    while True:
        #print('main True loop')
        await asyncio.gather(client.receive(processSignals), parseDatObject(processSignals))
        # await future_main() go here

asyncio.run(main())