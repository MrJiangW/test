function resources_loader(imgs){
	if(!imgs) return;
	if (typeof imgs != 'object') imgs = imgs.split(',');
	var nullfunc = function(){};
	var imgs_arr = [],
		imgs_count = 0;
	for(var i = 0 , l = imgs.length;i < l;i++){
		imgs_arr[i] = new Image();
		imgs_arr[i].src = imgs[i];
		imgs_arr[i].onload = imgloadadd;
		imgs_arr[i].onerror = imgloadadd;		
	}

	function imgloadadd(){
		imgs_count++;
		if(imgs_count == imgs.length){
			nullfunc(imgs_arr);
		}
	}

	return {
		done:function(cbk){
			nullfunc = cbk || nullfunc;
		}
	}
}