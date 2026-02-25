(function(window, document){
  var html5Els = 'article aside figcaption figure footer header hgroup main nav section time'.split(' ');
  var i;
  for (i = 0; i < html5Els.length; i++) {
    try { document.createElement(html5Els[i]); } catch (e) {}
  }

  if (!window.JSON) {
    window.JSON = {
      parse: function(str){ return (new Function('return ' + str))(); },
      stringify: function(obj){ return String(obj); }
    };
  }

  if (!Array.prototype.forEach) {
    Array.prototype.forEach = function(cb, ctx) {
      var j;
      for (j = 0; j < this.length; j++) {
        if (j in this) { cb.call(ctx, this[j], j, this); }
      }
    };
  }

  if (!String.prototype.trim) {
    String.prototype.trim = function(){
      return this.replace(/^\s+|\s+$/g, '');
    };
  }

  if (!window.Promise) {
    window.Promise = function(executor) {
      var state = 'pending';
      var value;
      var callbacks = [];

      function flush() {
        setTimeout(function(){
          var idx;
          for (idx = 0; idx < callbacks.length; idx++) {
            callbacks[idx](state, value);
          }
        }, 0);
      }

      function resolve(v) {
        if (state !== 'pending') { return; }
        state = 'fulfilled';
        value = v;
        flush();
      }

      function reject(r) {
        if (state !== 'pending') { return; }
        state = 'rejected';
        value = r;
        flush();
      }

      this.then = function(onFulfilled, onRejected) {
        return new window.Promise(function(res, rej){
          callbacks.push(function(currentState, currentValue){
            try {
              if (currentState === 'rejected') {
                if (typeof onRejected === 'function') { res(onRejected(currentValue)); }
                else { rej(currentValue); }
              } else {
                if (typeof onFulfilled === 'function') { res(onFulfilled(currentValue)); }
                else { res(currentValue); }
              }
            } catch (e) {
              rej(e);
            }
          });
        });
      };

      try { executor(resolve, reject); } catch (e2) { reject(e2); }
    };

    window.Promise.prototype.catch = function(cb){
      return this.then(null, cb);
    };

    window.Promise.resolve = function(v){
      return new window.Promise(function(res){ res(v); });
    };

    window.Promise.reject = function(err){
      return new window.Promise(function(res, rej){ rej(err); });
    };
  }

  if (!window.fetch) {
    window.fetch = function(url, opts){
      opts = opts || {};
      return new window.Promise(function(resolve, reject){
        var xhr = new XMLHttpRequest();
        var headers, h;

        try { xhr.open(opts.method || 'GET', url, true); } catch (e) { reject(e); return; }

        headers = opts.headers;
        if (headers) {
          for (h in headers) {
            if (headers.hasOwnProperty(h)) { xhr.setRequestHeader(h, headers[h]); }
          }
        }

        xhr.onreadystatechange = function(){
          var status;
          var ok;
          var response;
          if (xhr.readyState !== 4) { return; }

          status = xhr.status === 1223 ? 204 : xhr.status;
          ok = (status >= 200 && status < 300) || status === 0;

          response = {
            ok: ok,
            status: status,
            statusText: xhr.statusText,
            url: url,
            text: function(){
              return new window.Promise(function(resText){ resText(xhr.responseText); });
            },
            json: function(){
              return new window.Promise(function(resJson, rejJson){
                try { resJson(window.JSON.parse(xhr.responseText)); }
                catch (e2) { rejJson(e2); }
              });
            }
          };

          if (ok) { resolve(response); }
          else { reject(new Error('网络错误(' + status + ')')); }
        };

        xhr.onerror = function(){ reject(new Error('网络错误')); };

        try { xhr.send(opts.body || null); }
        catch (e3) { reject(e3); }
      });
    };
  }
})(window, document);
