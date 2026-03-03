// checkBraces.js
const fs = require('fs');
const path = require('path');

// Make sure this path points to your retrade.js file
const filePath = path.join(__dirname, 'retrade.js');

try {
    const code = fs.readFileSync(filePath, 'utf-8');

    let stack = [];
    let line = 1;

    for (let i = 0; i < code.length; i++) {
        const char = code[i];
        if (char === '\n') line++;
        if (char === '{' || char === '(') stack.push({ char, line });
        if (char === '}') {
            const last = stack.pop();
            if (!last || last.char !== '{') {
                console.log(`Unmatched } at line ${line}`);
            }
        }
        if (char === ')') {
            const last = stack.pop();
            if (!last || last.char !== '(') {
                console.log(`Unmatched ) at line ${line}`);
            }
        }
    }

    if (stack.length) {
        stack.forEach(s => console.log(`Unmatched ${s.char} opened at line ${s.line}`));
    } else {
        console.log('All braces matched!');
    }
} catch (err) {
    console.error('Error reading file:', err.message);
}
