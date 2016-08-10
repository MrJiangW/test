
// 想将对象冻结，应该使用Object.freeze方法
/*const foo = Object.freeze({});
常规模式时，下面一行不起作用；
严格模式时，该行会报错
foo.prop = 123;*/

// 解析赋值
/*var [a,b,c] = [1,3,4];
console.log(a);

var [head,...tail] = [1,3,4,5];
console.log(head,tail);*/
// let [x, y, z] = new Set(["a", "b", "c"]);

// 默认赋值
/*var [foo = true] = [];
foo // true

[x, y = 'b'] = ['a']; // x='a', y='b'
[x, y = 'b'] = ['a', undefined]; // x='a', y='b'*/

/*let x = 'x',
	y = 'y';
[x,y] = [y,x];
console.log(x,y)*/

/*function example() {
  return [1, 2, 3];
}
var [a, b, c] = example();*/

/*for (let codePoint of 'foo') {
  console.log(codePoint)
}*/

/*includes()：返回布尔值，表示是否找到了参数字符串。
startsWith()：返回布尔值，表示参数字符串是否在源字符串的头部。
endsWith()：返回布尔值，表示参数字符串是否在源字符串的尾部。
var s = 'Hello world!';

s.startsWith('Hello') // true
s.endsWith('!') // true
s.includes('o') // true*/

/*repeat()
repeat方法返回一个新字符串，表示将原字符串重复n次。*/
/*var dd = '123';
var ff = `123+${dd}`;
console.log(ff)*/

/*function fn() {
  return "Hello World";
}

alert(`foo ${fn()} bar`);*/



/*let arr = [1,3,4,5];
var str = `
		<ul>
		  <% for(var i=0; i < arr.length; i++) { %>
		    <li><%= arr[i] %></li>
		  <% } %>
		</ul>	
	`;*/



class firstclass {
		constructor(x,y) {
			// code
			this.x = x;
			this.y = y;
		}

		show(){
			console.log(this.x,this.y);
		}
	}

var func = x => {
	if(x>2){
		return true;
	}else{
		return false;
	}
};

