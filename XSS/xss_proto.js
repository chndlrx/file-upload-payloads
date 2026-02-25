Object.prototype.innerHTML = '<img src=x onerror=alert(1)>';
document.body.appendChild(Object.assign(document.createElement('div'), {}));
