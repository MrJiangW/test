var path = require('path');
var webpack = require('webpack');

// 每当 "react" 在代码中被引入，它会使用压缩后的 React JS 文件，而不是到 node_modules 中找。
// 每当 Webpack 尝试去解析那个压缩后的文件，我们阻止它，因为这不必要。
var node_modules = path.resolve(__dirname, 'node_modules');
var pathToReact = path.resolve(node_modules, 'react/dist/react.min.js');
var pathToReactDOM = path.resolve(node_modules, 'react-dom/dist/react-dom.min.js');

// 生成html模板
var HtmlWebpackPlugin = require("html-webpack-plugin");

// 压缩资源
var uglifyJsPlugin = webpack.optimize.UglifyJsPlugin;

var config = {
    entry: [
    	'webpack/hot/dev-server',   // 浏览器自动刷新  npm run dev
      	'webpack-dev-server/client?http://localhost:8080',  // 指定刷新 要 服务  
      	// http://localhost:8080/webpack-dev-server/bundle   提示框架预览模式  
    	path.resolve(__dirname, 'app/main.js')
    ],
    // resolveLoader: { root: path.join(__dirname, "node_modules") },
    resolve: {
        alias: {
          'react': pathToReact,
          'react-dom':pathToReactDOM
        }
    },
    output: {
        path: path.resolve(__dirname, 'build'),
        filename: 'bundle.js',
        publicPath: '/',
	    // filename: '[name].[hash].js',
	    // chunkFilename: '[id].[chunkhash].js'
    },
	// devtool: 'source-map',//  容错显示
	devServer: {
        historyApiFallback:true // history 使用browserHistory
    },
    module: {
	    loaders: [{
	      test: /\.jsx?$/, // 用正则来匹配文件路径，这段意思是匹配 js 或者 jsx
	      loader: 'babel?presets[]=react,presets[]=es2015', // 加载模块 "babel" 是 "babel-loader" 的缩写
          exclude: /node_modules/
	      // query:{
	      // 	presets: ['es2015']
	      // }
	    }, {
	      test: /\.css$/, // Only .css files
	      loader: "style!css!autoprefixer" // Run both loaders css-loader会遍历 CSS 文件，然后找到 url() 表达式然后处理他们，style-loader 会把原来的 CSS 代码插入页面中的一个 style 标签中
	    }, 
	    // LESS
	    {
	      test: /\.less$/,
	      loader: 'style!css!less'
	    },

	    // SASS
	    {
	      test: /\.scss$/,
	      loader: 'style!css!sass!autoprefixer'
	    }, {
	      test: /\.(png|jpg)$/,
	      loader: 'url?limit=25000'
	    }],
        noParse: [pathToReact,pathToReactDOM]
  	},
  	plugins: [
	    new HtmlWebpackPlugin({
            title: 'react webpack',
            template: 'app/index.html',
        }),
        // new uglifyJsPlugin({
        //     compress: {
        //         warnings: false
        //     }
        // })
	]
};
module.exports = config;