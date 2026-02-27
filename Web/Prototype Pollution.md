## 🧬 JavaScript Inheritance Models

JavaScript utilizes two primary inheritance paradigms governing object property resolution.

* Prototype-based Inheritance: Every object possesses a prototype from which it inherits properties and methods. Prototypes are assigned during instantiation via Object.create() or through direct modification of the existing prototype property.
* Class-based Inheritance: Introduced as syntactic sugar to mask underlying prototype mechanisms. Classes continue to utilize the prototype chain internally for inheritance structures.

## 🚨 Prototype Pollution Fundamentals

The Object prototype contains inherent properties frequently targeted for exploitation.


* constructor: References the function responsible for constructing an object's prototype.
* __proto__: References the prototype object from which the current object directly inherits.

The Golden Rule of prototype pollution dictates that if an attacker controls variables in property assignment paths, global prototype modification occurs.

* Path Assignment Person[x][y] = val: If x is assigned as __proto__, the attribute defined by y is globally instantiated across all objects sharing the class.
* Path Assignment Person[x][y][z] = val: If x is assigned as constructor and y as prototype, the property z is globally defined with val. This vector requires complex property arrangements and is less frequent in standard application logic.

## ⚙️ Vulnerable Object Manipulation Functions

Penetration testing must focus on identifying functions susceptible to unsafe object manipulation and missing input sanitization.

Property Definition by Path
Functions establishing properties via explicit paths (e.g., object[a][b][c] = value) are vulnerable if path components remain uncontrolled. Path traversal into the object prototype must be explicitly restricted.

Object Recursive Merge
Functions merging source object properties into target objects recursively. Exploitation occurs when merge operations fail to validate inputs, permitting prototype chain contamination.

```javascript
# Vulnerable recursive merge function and endpoint
function recursiveMerge(target, source) {
    for (let key in source) {
        if (source[key] instanceof Object) {
            if (!target[key]) target[key] = {};
            recursiveMerge(target[key], source[key]);
        } else {
            target[key] = source[key];
        }
    }
}

app.post('/updateSettings', (req, res) => {
    const userSettings = req.body; 
    recursiveMerge(globalUserSettings, userSettings);
    res.send('Settings updated!');
});
```
* Tool: Node.js

To exploit the recursive merge, supply a nested object manipulating the prototype.

```json
# Prototype pollution payload
{ 
  "__proto__": { 
    "newProperty": "value" 
  } 
}
```
* Tool: Raw HTTP Client

Object Clone
Deep clone operations inadvertently replicating prototype chain properties. Functions must strictly clone user-defined attributes and filter protected keywords, including __proto__ and constructor.
