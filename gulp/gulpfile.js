var gulp = require('gulp'),
	autoprefixer = require('gulp-autoprefixer'),
	concat = require('gulp-concat'),
	imagemin = require('gulp-imagemin'),
	pngquant = require('imagemin-pngquant'), // 深度压缩
	cache = require('gulp-cache'),
	jshint = require('gulp-jshint'),
	uglify = require('gulp-uglify');
	cssmin = require('gulp-clean-css'),
	cssver = require('gulp-make-css-url-version'), 
	sass = require('gulp-ruby-sass'),
	notify = require('gulp-notify'),
	rename = require('gulp-rename'),
	htmlmin = require('gulp-htmlmin'),
	gulpUtil = require('gulp-util'),
	babel = require('gulp-babel'),
	livereload = require('gulp-livereload');

// 路径设置
var paths = {
	script:['src/js/**/*.js'], // js
	script_dist:'dist/js',
	css: ['src/css/**/*.css'], // css
	css_dist:'dist/css',
	html:['src/html/*.html'], // html
	html_dist:'dist/html',
	imgs:['src/images/*.{jpg,png,gif,ico}'], // image
	imgs_dist:'dist/images'
} 


// JS压缩
gulp.task('uglify',function(){
	gulp.src(paths.script)
		//.pipe(jshint())
		.pipe(babel({
			presets:['es2015']
		}).on('error',gulpUtil.log))
		.pipe(uglify({
            mangle: true,//类型：Boolean 默认：true 是否修改变量名
            compress: true,//类型：Boolean 默认：true 是否完全压缩
            preserveComments: '' //保留所有注释 'all'
        }).on('error', gulpUtil.log))   // .on('error', gulpUtil.log)   文件报错后继续执行 不中断跳出
		.pipe(rename({suffix:'.min'}))
		.pipe(gulp.dest(paths.script_dist))
		.pipe(livereload());
});

// CSS压缩
gulp.task('cssmin',function(){
	var options = {
		advanced: true,//类型：Boolean 默认：true [是否开启高级优化（合并选择器等）]
        compatibility: 'ie7',//保留ie7及以下兼容写法 类型：String 默认：''or'*' [启用兼容模式； 'ie7'：IE7兼容模式，'ie8'：IE8兼容模式，'*'：IE9+兼容模式]
        keepBreaks: false,//类型：Boolean 默认：false [是否保留换行]
        keepSpecialComments: '*' //保留所有特殊前缀 当你用autoprefixer生成的浏览器前缀，如果不加这个参数，有可能将会删除你的部分前缀
	}
	gulp.src(paths.css)
		.pipe(autoprefixer({
            browsers: ['last 2 versions', 'Android >= 4.0'],
            cascade: true, //是否美化属性值 默认：true 像这样：
            //-webkit-transform: rotate(45deg);
            //        transform: rotate(45deg);
            remove:true //是否去掉不必要的前缀 默认：true 
        }))
		.pipe(cssver()) //给css文件里引用文件加版本号（文件MD5）
		.pipe(cssmin(options))
		.pipe(rename({suffix:'.min'}))
		.pipe(gulp.dest(paths.css_dist))
		.pipe(livereload());	
})

// HTML 压缩
gulp.task('htmlmin', function () {
    var options = {
        removeComments: true,//清除HTML注释
        collapseWhitespace: true,//压缩HTML
        collapseBooleanAttributes: true,//省略布尔属性的值 <input checked="true"/> ==> <input />
        removeEmptyAttributes: true,//删除所有空格作属性值 <input id="" /> ==> <input />
        removeScriptTypeAttributes: true,//删除<script>的type="text/javascript"
        removeStyleLinkTypeAttributes: true,//删除<style>和<link>的type="text/css"
        minifyJS: true,//压缩页面JS
        minifyCSS: true//压缩页面CSS
    };
    gulp.src(paths.html)
    	.pipe(livereload())
        .pipe(htmlmin(options))
        .pipe(gulp.dest(paths.html_dist));
});

// 图片压缩
gulp.task('imagemin',function(){
	var options = {
		optimizationLevel: 5, //类型：Number  默认：3  取值范围：0-7（优化等级）
        progressive: true, //类型：Boolean 默认：false 无损压缩jpg图片
        interlaced: true, //类型：Boolean 默认：false 隔行扫描gif进行渲染
        multipass: true, //类型：Boolean 默认：false 多次优化svg直到完全优化
        svgoPlugins: [{removeViewBox: false}],//不要移除svg的viewbox属性
        use: [pngquant()] //使用pngquant深度压缩png图片的imagemin插件
	};
	gulp.src(paths.imgs)
		.pipe(cache(imagemin(options)))  // 压缩图片比较耗时  用cache插件
		.pipe(gulp.dest(paths.imgs_dist));
})

// 文件监听
gulp.task('watch',function(){
	livereload.listen();
	gulp.watch(paths.script,['uglify']);
	gulp.watch(paths.css,['cssmin']);
	gulp.watch(paths.html,['htmlmin']);
});


// 默认任务列队
gulp.task('default',['uglify','htmlmin','cssmin','watch']);


