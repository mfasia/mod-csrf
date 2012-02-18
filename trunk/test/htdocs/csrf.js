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

var types = [
	     ["a",          "href" ],
	     ["area",       "href" ],
	     ["applet",     "codebase" ],
	     ["base",       "href" ],
	     ["blockquote", "cite" ],
	     ["body",       "background", "style" ],
	     ["del",        "cite" ],
	     ["form",       "action" ],
	     ["frame",      "src", "longdesc" ],
	     ["head",       "profile" ],
	     ["iframe",     "src", "longdesc" ],
	     ["img",        "src", "longdesc", "usemap" ],
	     ["input",      "src", "usemap" ],
	     ["ins",        "cite" ],
	     ["link",       "href" ],
	     ["meta",       "content" ],
	     ["object",     "classid", "codebase", "data", "usemap" ],
	     ["p",          "style" ],
	     ["q",          "cite" ],
	     ["script",     "src", "for" ],
	     ["table",      "style" ],
	     ["td",         "style" ],
	     ["tr",         "style" ],
	     ];


function csrfInsert(csrfId) {
  document.write("query to add: " + csrfId + "<br/>");

  var links = document.links;
  document.write("number of links: " + links.length + "<br/>");

  var forms = document.getElementsByTagName("form");
  document.write("number of forms: " + forms.length + "<br/>");

  var i;
  for(i = 0; i < types.length; i++) {
    var name = types[i][0];
    var nodes = document.getElementsByTagName(name);
    document.write("number of '" + name + "' nodes: " + nodes.length + "<br/>");
  }
}
