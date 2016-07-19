/*
2016-06-24
初识 require
*/
// 对模块的加载行为进行自定义
require.config({
	// baseUrl:'lib',  //设置基目录
	paths:{
		'jquery':'jquery.min'
	}
})

// 调用math模块
require(['math','jquery'],function(math,$){
	// alert(math.add(7,7));
	// $('body').css('background', 'green');
})