import argparse
import numpy as np
import pandas as pd
import xml.etree.ElementTree as ET
from xml.etree.ElementTree import ParseError
from datetime import datetime
#import matplotlib.pyplot as plt
import sys

#global variable
data = []

def parseDatObject(datBlob):
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
            data.append({'timestamp': formatted_time, 'name': name, 'val': val})
    elif url.startswith('rel') or url.startswith('chassis') or url.startswith('acceleratorPosition'):
        rel_tag = datBlob.find('Rel')
        name = rel_tag.get('name')
        val = rel_tag.get('val')
        data.append({'timestamp': formatted_time, 'name': name, 'val': val})
    else:
    #    print('timestamp: ', timestamp, ' url: ', url, 'abs: ', dat.find('Abs').get('name'), 'val: ',dat.find('Abs').get('val') )
        abs_tag = datBlob.find('Abs')
        name = abs_tag.get('name')
        val = abs_tag.get('val')
        data.append({'timestamp': formatted_time, 'name': name, 'val': val})
       
def saveToCsv(outputFile):
    df = pd.DataFrame(data)

    # Set the option to display all values without truncation
    np.set_printoptions(threshold=np.inf)
    pd.set_option('display.max_rows', None)

    df.to_csv(outputFile, index = False )

def main():
    
    parser = argparse.ArgumentParser(description="Convert EXLAP XML file to csv file")
    parser.add_argument("inputFile", help="Path to the XML file")
    parser.add_argument("outputFile", help="Output file name")

    args = parser.parse_args()
    inputFile = args.inputFile
    outputFile = args.outputFile
        
    try:
        tree = ET.parse(inputFile)
        for element in tree.findall('.//Dat'):
            print("processing: ", element.get('timeStamp'), element.get('url'))
            parseDatObject(element)
        
        saveToCsv(outputFile)
    
    except ET.ParseError as e:
        print('XML Parse Error:: ', e)
        print('.....line: ', e.position[0], 'column: ', e.position[1])
        quit()

if __name__ == "__main__":
    main()

'''
root = tree.getroot()
data= []
count = 0;
for dat in root.findall('Dat'):
    timestamp = dat.get('timeStamp')
    url = dat.get('url')
    print('Processing timestamp: ', timestamp, ' URL: ', url)
     
    #handle special cases such as (i) multiple values for espTyreVelocities, (ii) <Rel> instead of <Abs> for some commands
    if url == 'espTyreVelocities' or url == 'Nav_GeoPosition':
     #   print('timestamp:', timestamp, ' found ', url)
        abs_tags = dat.findall('Abs')
        for abs_tag in abs_tags:
            name = url + '_' + abs_tag.get('name')
            val = abs_tag.get('val')
            data.append({'timestamp': timestamp, 'name': name, 'val': val})
    elif url.startswith('rel') or url.startswith('chassis') or url.startswith('acceleratorPosition'):
        rel_tag = dat.find('Rel')
        name = rel_tag.get('name')
        val = rel_tag.get('val')
        data.append({'timestamp': timestamp, 'name': name, 'val': val})
    else:
    #    print('timestamp: ', timestamp, ' url: ', url, 'abs: ', dat.find('Abs').get('name'), 'val: ',dat.find('Abs').get('val') )
        abs_tag = dat.find('Abs')
        name = abs_tag.get('name')
        val = abs_tag.get('val')
        data.append({'timestamp': timestamp, 'name': name, 'val': val})
       

df = pd.DataFrame(data)

# Set the option to display all values without truncation
np.set_printoptions(threshold=np.inf)
pd.set_option('display.max_rows', None)

df.to_csv('testlog.csv', index = False )
'''
'''
filter_df = df[df['name'] == 'relAllWheelClutchTorque']
awd_values = pd.to_numeric(filter_df['val'])
change_count = sum(awd_values.diff() != 0)
df[df['name'] == 'yawRate']['val'] = pd.to_numeric(df[df['name'] == 'yawRate']['val'])
print("Yaw Rate max:", df[df['name'] == 'yawRate']['val'].max(), " min: ", df[df['name'] == 'yawRate']['val'].min(), "num of changes: ", sum(df[df['name'] == 'yawRate']['val'].diff() != 0))
print("AWD Clutch Torque: max ", filter_df['val'].max(), "min: ",filter_df['val'].min(), "# of changes: ", change_count)
#print(awd_values.values)
'''
'''
#Trying to Plot a Graph
df['timestamp'] = pd.to_datetime(df['timestamp'])
df.set_index('timestamp', inplace=True)

#plt.figure(figsize=(10,6))
plt.plot(filter_df['timestamp'], filter_df['val'])
plt.xlabel('Timestamp')
plt.ylabel('awd clutch torque')
plt.grid(True)
plt.show()
'''