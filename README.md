# injected-notify
http注入感知、防御工具 /A lib to do callback when http site be injected by network operator

## Usage
```bash
npm i injected-notify --save
```

### In common
```js
  const InjectedNotify = require('injected-notify');
  InjectedNotify.init(['alicdn.com'], true, function(injectUrl) {
    // injectUrl = ['xxx.com/xxx.js','xxx.cn/xxx.js']
  });
```

### In Browers
```html
<head>
    <script src="./injected-notify.js"></script>
    <script>(function () {
        window.global_injected_notify.init(['alicdn.com'], true, function(injectUrl) {
          // injectUrl = ['xxx.com/xxx.js','xxx.cn/xxx.js']
        });
      })()
    </script>
</head>
```
