// === Objects & Arrays Test ===

// Object literal
let user = {name: "Amrit", age: 20, lang: "C"}
console.log(user.name)
console.log(user.age)
console.log(user.lang)

// Array literal
let nums = [10, 20, 30, 40, 50]
console.log(nums)
console.log(nums.length)

// Array push
let items = [1, 2, 3]
items.push(4)
items.push(5)
console.log(items)

// JSON.stringify
console.log(JSON.stringify(user))
console.log(JSON.stringify(nums))
console.log(JSON.stringify({status: "ok", code: 200}))

// String methods
let msg = "Hello World"
console.log(msg.toUpperCase())
console.log(msg.toLowerCase())
console.log(msg.length)
console.log(msg.includes("World"))

// Nested object
let server = {host: "localhost", port: 4433, tls: true}
console.log(JSON.stringify(server))
