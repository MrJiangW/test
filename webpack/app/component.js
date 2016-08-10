'use strict';

module.exports = function(){
	var element = document.createElement('h1');
	element.innerHTML = '这么神奇啊 到底!<b style="color:green;">strong</b>';
	return element;
}