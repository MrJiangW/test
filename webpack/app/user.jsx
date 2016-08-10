// 'use strict';
import './Component.css';
import React from 'react';

import {Link} from 'react-router';

export default class Hello extends React.Component {
  render() {
    return <div>
      {this.props.children}
    </div>
  }
}