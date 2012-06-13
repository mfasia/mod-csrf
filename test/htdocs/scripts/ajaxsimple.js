
var counter1 = 0;
var counter2 = 0;

function autoStart() {
  setInterval("autoUpdate()", 1000);
  setInterval("autoSend()", 2000);
}

function autoSend() {
  var client = new XMLHttpRequest();
  client.onreadystatechange = sendHandler;
  client.open("GET", "/update.xml?id=123456789");
  client.send();
}

function sendHandler() {
  if(this.readyState == this.DONE) {
    if(this.status == 200 &&
       this.responseXML != null) {
      //var data = this.responseXML.getElementById("update");
      var update = document.getElementById("autosend");
      //update.innerHTML = data;
      counter2++;
      update.innerHTML = "== UPDATED from /update.xml == (" + this.responseText + ") " + counter2;
      return;
    }
  }
}

// automatically update the "autoupdate" div with the status fetched from the server
function autoUpdate() {
  var update = document.getElementById("autoupdate");
  if(window.XMLHttpRequest) { // non-IE browsers
    req = new XMLHttpRequest();
    req.onreadystatechange = statusDiv;
    try {
      //req.open("GET", "/update.txt", true);
      req.open("GET", "/update.txt?id=123", true);
    } catch (e) {
      // ignore
      update.innerHTML = "FAILED!!!";
    }
    req.send(null);
  } else if (window.ActiveXObject) { // IE
    req = new ActiveXObject("Microsoft.XMLHTTP");
    if (req) {
      req.onreadystatechange = statusDiv;
      req.open("GET", "/update.txt?id=123", true);
      req.send();
    }
  }
}

// callback
function statusDiv() {
  if (req.readyState == 4) { // Complete
    if (req.status == 200) { // OK response
      var update = document.getElementById("autoupdate");
      counter1++;
      update.innerHTML = req.responseText + " " + counter1;
    } else{
      var update = document.getElementById("autoupdate");
      update.innerHTML = "FAILED!!!";
    }
  }
}