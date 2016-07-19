# H5FullscreenPage
## Doc
H5FullscreenPage.init(options);

options:(default)

<pre>
{
    'type' : 1,
    'pageShow' : function(page){},
    'pageHide' : function(page){},
    'useShakeDevice' : {
        'speed' : 30,
        'callback' : function(page){}
    },
    'useParallax' : true,
    'useArrow' : true,
    'useAnimation' : true,
    'useMusic' : {
        'autoPlay' : true,
        'loopPlay' : true,
        'src' : 'http://mat1.gtimg.com/news/2015/love/FadeAway.mp3'
    }
 };
</pre>
####type
这个值有8种类型[1-8]，每种类型都有不同的滚动动画，你可以改变你自己。
####pageShow
在每一页的屏幕这个功能会给一个参数到这个页面的DOM。
####pageHide
从屏幕上的每一个网页后，此功能将给一个参数到这个页面的DOM。
####useShakeDevice
听shakedevice事件提供devicemotion接口需要速度和回调，给一个参数这个页面DOM运行时回调。
####useArrow
是使用箭头或不。
####useParallax
此选项将打开deviceorientation事件添加元素有类。视差，那么这个元素将通过移动装置。
####useAnimation
是使用部分动画或不。
####useMusic
是使用音乐或不使用，如果不使用该值为空。

###Use css animaion

<pre>
&lt;div class="part  slideRight" data-delay="1300"&gt;&lt;/div&gt;
</pre>

如果你想在你的网页使用CSS动画的形式。你可以添加一个类，并选择使用什么动画。数据延迟让动画延迟几秒钟运行。
####Animation list:
[fadeIn,slideLeft,slideRight,slideUp,slideDown,rotateIn,zoomIn,heartBeat,rollInLeft,rollInRight]
