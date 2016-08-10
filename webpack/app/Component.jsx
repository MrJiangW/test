// 'use strict';
import './Component.css';
import React from 'react';

export default class Hello extends React.Component {
  render() {
    return <h1>HOME<a href="/#/user/">USER</a></h1>;
  }
}