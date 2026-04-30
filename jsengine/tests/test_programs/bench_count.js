// === Operation Counter Benchmark ===

// Test 1: Million additions
let sum = 0
let i = 0
while (i < 1000000) {
    sum = sum + i
    i = i + 1
}
console.log("Sum 1M: " + sum)

// Test 2: Fibonacci iterative
function fib(n) {
    let a = 0
    let b = 1
    let j = 0
    while (j < n) {
        let temp = b
        b = a + b
        a = temp
        j = j + 1
    }
    return a
}
console.log("fib(40): " + fib(40))

// Test 3: Multiplications
let product = 1
let k = 1
while (k <= 100000) {
    product = (product * k) % 1000000007
    k = k + 1
}
console.log("Product mod: " + product)

// Test 4: Nested math
let result = 0
let n = 0
while (n < 100000) {
    result = result + (n * 3 + n / 2 - n % 7)
    n = n + 1
}
console.log("Complex math: " + result)
