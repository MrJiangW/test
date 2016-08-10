// 'use strict';

// var component = require('./component.js');

// document.body.appendChild(component());


import './main.scss';
import './main.css';
import React from 'react';
import ReactDOM from 'react-dom';
import Hello from './Component.jsx';
import User from './user.jsx';

const NotFound = React.createClass({
	render(){
		return(
		<div>NotFound!!!!!</div>
		)
	}
})

import { Router, Route,IndexRoute, hashHistory ,browserHistory,Link} from 'react-router';

const Index = React.createClass({
	render(){
		return (
			<div>
		        {this.props.params.id}
		      </div>
		    )
	}
});
const Userindex = React.createClass({
	render(){
		return (
			<div>/user/
		      </div>
		    )
	}
});
ReactDOM.render(
	<Router history={browserHistory}>
	    <Route path="/" component={Hello} />
	    <Route path="/user" component={User}>
	    	<IndexRoute component={Userindex}/>
	    	<Route path="dd/:id" component={Index} />
	    </Route>
	    <Route path="*" component={NotFound} />
	</Router>,	 
	document.getElementById('app')
);




// const routeConfig = [
// 	{
// 	    path: '/save',
// 	    component: Index
// 	},{
// 		path:'/user',
// 		component:User
// 	},
//   {
//     path: '*',
//     component: NotFound,
//   }
// ];


// ReactDOM.render((
//   <Router routes={routeConfig} history={hashHistory} />
// ), document.getElementById('app'));

// main();

// function main(){
//     ReactDOM.render(
//     	<div><Hello /><Hello /></div>,
//     	document.getElementById('app')
//     	);
// }