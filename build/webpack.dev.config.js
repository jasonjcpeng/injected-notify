const path = require('path');
const HtmlWebpackPlugin = require('html-webpack-plugin');
const CleanWebpackPlugin = require('clean-webpack-plugin');

module.exports = {
  mode: 'development',
  entry: path.resolve(__dirname, '../src/js/index.js'),
  devtool: 'inline-source-map',
  output: {
    path: path.resolve(__dirname, '../dist'),
    filename: 'index.[hash].js',
    publicPath: '/'
  },
  plugins: [
    new CleanWebpackPlugin([ '../dist' ]),
    new HtmlWebpackPlugin({
      template: path.resolve(__dirname, '../test/index.html'),
    })
  ],
  module: {
    rules: [
      {
        test: /\.js$/,
        exclude: /(node_modules|bower_components)/,
        use: {
          loader: 'babel-loader',
          options: {
            presets: [ '@babel/preset-env' ]
          }
        }
      }
    ]
  },
  devServer: {
    contentBase: path.join(__dirname, '../dist'),
  },
};