//
// mod_csrf - Cross-site request forgery protection module for
//            the Apache web server
//
// Copyright (C) 2012 Christoph Steigmeier, Pascal Buchbinder
// 
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 2.1 of the License, or (at your option) any later version.
// 
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.
// 
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
//

// TODO: additonal types (some may contain javascript fragments)
var types = [
	     ["a",          "href" ]
	     ];

// dynamic/ajax requests overriding the send function appending the id as a request header
function registerAjax(paramName, csrfId) {
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
      // add the id as a request header (don't want (know how) to modify the url)
      this.setRequestHeader(paramName, csrfId);
    }
};

// adds the csrfId to all known refernce nodes
function addToNodes(paramName, csrfId) {
  // iterate through all known types, e.g. "a"
  for(i = 0; i < types.length; i++) {
    var j;
    var name = types[i][0];
    // fetch all nodes from the document
    var nodes = document.getElementsByTagName(name);
    if(nodes != null) {
      for(j = 0; j < nodes.length; j++) {
	// process all attributes for these nodes, e.g. "href" for nodes of type "a"
	var ai = 1;
	while(types[i][ai] != null) {
	  var attribute = nodes[j].getAttribute(types[i][ai]);
	  if(attribute != null) {
	    if(attribute.indexOf("?") == -1) {
	      var newattribute = attribute + "?" + paramName + "=" + csrfId;
	      nodes[j].setAttribute(types[i][ai], newattribute);
	    } else {
	      var newattribute = attribute + "&" + paramName + "=" + csrfId;
	      nodes[j].setAttribute(types[i][ai], newattribute);
	    }
	  }
	  ai++;
	}
      }
    }
  }
}

// adds the csrfId as a hidden field to every form
function addToForms(paramName, csrfId) {
  var nodes = document.getElementsByTagName('form');
  for(var i = 0; i < nodes.length; i++) {
    var link = document.createElement('input');
    link.setAttribute('type', 'hidden');
    link.setAttribute('name', paramName);
    link.setAttribute('value', csrfId);
    nodes[i].appendChild(link);
  }
}

function csrfInsert(paramName, csrfId) {
//  var i;
//  document.write("id to add: " + csrfId + "<br/>");
//  document.write("domain: " + document.domain + "<br/>");
//
//  var links = document.links;
//  document.write("number of links: " + links.length + "<br/>");
//
//  var forms = document.getElementsByTagName("form");
//  document.write("number of forms: " + forms.length + "<br/>");

  // register callbacks when sending data by the browser
  registerAjax(paramName, csrfId);

  // simple references
  addToNodes(paramName, csrfId);

  // forms
  addToForms(paramName, csrfId);
}
