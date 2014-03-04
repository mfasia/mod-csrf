

function registerRedirect() {
    XMLHttpRequest.prototype._open = XMLHttpRequest.prototype.open;
    XMLHttpRequest.prototype.open = function(method, url, async, user, pass) {
      this._open.apply(this, arguments);
    }
    XMLHttpRequest.prototype._send = XMLHttpRequest.prototype.send;
    XMLHttpRequest.prototype.send = function(data) {
      if(this.onsend != null) {
	this.onsend.apply(this, arguments);
      }
      this._send.apply(this, arguments);
    }
    XMLHttpRequest.prototype.onsend = function(data) {
      this.addEventListener("readystatechange", function() {
			      var location = this.getResponseHeader("X-LoginPage");
			      if(location != null) {
                                window.location = "/login.html?login";
			      }
			    }, false);

      //var location = this.getResponseHeader("Location");
      //alert(location);
    }
//    XMLHttpRequest.prototype.getAllResponseHeaders = function() {
//      var headers = this.object.getAllResponseHeaders();
//      alert("123");
//      return headers;
//    };
//
//    XMLHttpRequest.prototype.onreadystatechange = function() {
//      var location = this.getResponseHeader("Location");
//      alert(location);
//    };

};
