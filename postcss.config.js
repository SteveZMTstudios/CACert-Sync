module.exports = {
  plugins: [
    require('autoprefixer')({
      overrideBrowserslist: [
        'safari >= 5',
        'iOS >= 3',
        'Android >= 2.0',
        'ie >= 5',
        'Firefox >= 3.6',
        'Chrome >= 4'
      ],
      // Ensure older flexbox syntax is emitted
      flexbox: 'no-2009',
      grid: false
    })
  ]
};
