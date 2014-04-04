
function registerRedirect() {
    var req = window.XMLHttpRequest;
    if(!req) {
      // compat to older IE versions
      req = new ActiveXObject("Microsoft.XMLHTTP"); 
    }
    req.prototype._send = req.prototype.send;
    req.prototype.send = function(data) {
      if(this.onsend != null) {
	this.onsend.apply(this, arguments);
      }
      this._send.apply(this, arguments);
    }
    req.prototype.onsend = function(data) {
      this.addEventListener("readystatechange", function() {
			      var auth = this.getResponseHeader("X-LoginPage");
			      //if(auth != null && auth != "valid") {
			      if(auth != null) {
                                window.top.onbeforeunload = null;
                                window.top.location = "/login.html?loginl";
			      }
			    }, false);
    }
};

