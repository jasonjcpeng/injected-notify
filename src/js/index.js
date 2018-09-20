class Module{
  constructor(){
    this.IP_REGEX = '^(?:https?:)?\/{2}(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])';
    this.injectUrl = [];
  }

  /**
   * 判断是否是白名单url
   * @param url
   * @returns {boolean}
   */
  isWhite(url) {
    if (!url || !Array.prototype.some) {
      return true;
    }

    // 先检测 IP, 是ip统一上报
    var ip = url.match(new RegExp(this.IP_REGEX, 'i'));
    if (ip && ip[ 0 ]) {
      return false;
    }

    // 不是http://,https://,// 开头的不拦截
    if (!/^(https?:\/\/|\/\/)/.test(url)) {
      return true;
    }

    return this.whiteDomainRegList.some(function(item) {
      var domain = url.match(/^(?:https?:)?\/{2}?(?:[^@\n]+@)?(?:www\.)?([^:\/\n]+)/im);
      return item.test(domain && domain[ 1 ]);
    });
  };

  /**
   * 重写元素的setAttribute 进行 script拦截
   */
  setAttribute() {
    var self = this;

    if (typeof Element !== 'undefined') {

      // 保存上级接口
      var setAttribute = Element.prototype.setAttribute;

      // 勾住当前接口
      Element.prototype.setAttribute = function (name, value) {
        if (this.tagName === 'SCRIPT' && /^src$/i.test(name)) {
          if (!self.isWhite(value)) {
            self.injectUrl.push(value);
            console.warn('[injected-notify] Detect malicious:', value, '.If it is a mistack, please add white domain');
            return;
          }
        }
        setAttribute.apply(this, arguments);
      };
    }
  };

  /**
   * 重写元素的createElement 进行 script拦截
   */
  createElement() {
    var self = this;

    if (typeof Document !== 'undefined') {
      // 保存上级接口
      var createElement = Document.prototype.createElement;

      Document.prototype.createElement = function () {

        var element = createElement.apply(this, arguments);

        if (element.tagName === 'SCRIPT') {
          try {
            Object.defineProperty(element, 'src', {
              set: function (url) {
                if (!self.isWhite(url)) {
                  self.injectUrl.push(url);
                  console.warn('[injected-notify] Detect malicious:', url, '.If it is a mistack, please add white domain');
                } else {
                  Element.prototype.setAttribute.call(element, 'src', url);
                }
              },
              get: function () {
                return this.getAttribute('src');
              }
            });
          } catch (err) {
            console.error('[injected-notify] Unable to hook `document.createElement` on `src`, ignored.');
          }
        }

        return element;
      };
    }
  };
  // 检查文档中远程脚本地址
  checkDocumentScript() {
    for (const i in document.scripts){

      const url = document.scripts[ i ].src;

      if (!this.isWhite(url)){
        this.injectUrl.push(url);
      }
    }
  }

  // 初始化
  init(arr, isDefense, callback){
    if (typeof arr !== 'object') return;

    arr.push('localhost');

    this.whiteDomainRegList = arr.map(function(item) {
      var regexStr = item.replace(/[-[\]{}()*+?.,\\^$|#\s]/g, '\\$&');

      return new RegExp([ '((\\*|[\\w\\d]+(-[\\w\\d]+)*)\\.)*(', regexStr, ')' ].join(''), 'i');
    });

    isDefense ? this.defense() : '';

    callback ? this.doSomething(callback) : '';
  }
  // 注入防御
  defense(){
    if (typeof Object.defineProperty == 'function') {
      this.setAttribute();

      this.createElement();
    }
  }
  // 发现被注入后做什么事
  doSomething(callback) {
    window.setTimeout(() => {
      this.checkDocumentScript();

      callback(this.injectUrl);
    }, 500);

  }
}

let exModule;

window.global_injected_notify = exModule = new Module();

if(module && module.exports){
  module.exports = exModule;
}