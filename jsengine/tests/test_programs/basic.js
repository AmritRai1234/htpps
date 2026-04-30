// === JS Engine Test Suite ===
// Tests all Phase 1 & 2 features

// --- Arithmetic (runs in assembly!) ---
console.log(2 + 3)
console.log(10 - 4)
console.log(6 * 7)
console.log(22 / 7)
console.log(17 % 5)

// --- Strings ---
console.log("hello" + " " + "world")
console.log("result: " + 42)

// --- Variables ---
let x = 100
let y = x + 50
console.log(y)

// --- Functions ---
function add(a, b) {
    return a + b
}
console.log(add(10, 20))

function greet(name) {
    return "Hello, " + name + "!"
}
console.log(greet("Amrit"))

// --- If/Else ---
let score = 85
if (score > 90) {
    console.log("A grade")
} else {
    console.log("B grade")
}

// --- Loops ---
let sum = 0
let i = 1
while (i <= 10) {
    sum = sum + i
    i = i + 1
}
console.log("Sum 1-10: " + sum)

// --- Math builtins ---
console.log(Math.floor(3.7))
console.log(Math.sqrt(144))

// --- Comparison & logic ---
console.log(5 > 3)
console.log(10 === 10)
console.log(true && false)
console.log(true || false)

// --- Bitwise (converted to int32, computed in ASM) ---
console.log(5 | 3)
console.log(5 & 3)
console.log(5 ^ 3)
console.log(1 << 4)
