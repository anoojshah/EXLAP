import argparse
import xml.etree.ElementTree as ET

def find_malformed_xml_line(file_path):
    try:
        with open(file_path, 'r') as file:
            xml_data = file.read()
            ET.fromstring(xml_data)  # Try to parse the XML
            return None  # XML is well-formed
    except ET.ParseError as e:
        # An error occurred, indicating malformed XML
        # e.position contains (line, column) information about the error
        return e

def main():
    parser = argparse.ArgumentParser(description="Check if an XML file is well-formed.")
    parser.add_argument("file", help="Path to the XML file")

    args = parser.parse_args()
    file_path = args.file

    validity = find_malformed_xml_line(file_path)

    if validity. is None:
        print(f"The XML in '{file_path}' is well-formed.")
    else:
        print(f"Malformed XML in '{file_path}' on line {line_number}.")

if __name__ == "__main__":
    main()
