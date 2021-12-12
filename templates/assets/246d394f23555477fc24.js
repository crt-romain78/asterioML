"use strict";(this.webpackChunkdiscord_app=this.webpackChunkdiscord_app||[]).push([[4688],{498773:(e,t,n)=>{Object.defineProperty(t,"__esModule",{value:!0});t.default=void 0;var o,r=function(e,t){if(!t&&e&&e.__esModule)return e;if(null===e||"object"!=typeof e&&"function"!=typeof e)return{default:e};var n=g(t);if(n&&n.has(e))return n.get(e);var o={},r=Object.defineProperty&&Object.getOwnPropertyDescriptor;for(var a in e)if("default"!==a&&Object.prototype.hasOwnProperty.call(e,a)){var i=r?Object.getOwnPropertyDescriptor(e,a):null;i&&(i.get||i.set)?Object.defineProperty(o,a,i):o[a]=e[a]}o.default=e;n&&n.set(e,o);return o}(n(667294)),a=b(n(294184)),i=b(n(973935)),u=b(n(536211)),l=b(n(235879)),s=b(n(647817)),c=b(n(871778)),f=b(n(230165)),d=n(430138),p=b(n(692711)),v=b(n(657138)),h=n(843519),y=["autoplay","reduceMotion"],m=["emojiName","animated","className","size","alt","shouldAnimate","isFocused","emojiId","autoplay","isInteracting"];function b(e){return e&&e.__esModule?e:{default:e}}
function g(e){if("function"!=typeof WeakMap)return null;var t=new WeakMap,n=new WeakMap;return(g=function(e){return e?n:t})(e)}function O(e,t,n,r){o||(o="function"==typeof Symbol&&Symbol.for&&Symbol.for("react.element")||60103);var a=e&&e.defaultProps,i=arguments.length-3;t||0===i||(t={children:void 0});if(1===i)t.children=r;else if(i>1){for(var u=new Array(i),l=0;l<i;l++)u[l]=arguments[l+3];t.children=u}if(t&&a)for(var s in a)void 0===t[s]&&(t[s]=a[s]);else t||(t=a||{});return{$$typeof:o,type:e,key:void 0===n?null:""+n,ref:null,props:t,_owner:null}}function j(e,t){if(null==e)return{};var n,o,r={},a=Object.keys(e);for(o=0;o<a.length;o++){n=a[o];t.indexOf(n)>=0||(r[n]=e[n])}return r}function M(e,t){e.prototype=Object.create(t.prototype);e.prototype.constructor=e;w(e,t)}function w(e,t){w=Object.setPrototypeOf||function(e,t){e.__proto__=t;return e};return w(e,t)}function _(){_=Object.assign||function(e){for(var t=1;t<arguments.length;t++){var n=arguments[t]
;for(var o in n)Object.prototype.hasOwnProperty.call(n,o)&&(e[o]=n[o])}return e};return _.apply(this,arguments)}var E=function(e){M(t,e);function t(){for(var t,n=arguments.length,o=new Array(n),r=0;r<n;r++)o[r]=arguments[r];(t=e.call.apply(e,[this].concat(o))||this).state={hover:!1};t.key=void 0;t.onError=function(){var e=t.getSrc();null!=e&&(t.cancelLoadImage=(0,h.loadImage)(e,(function(e){if(!e){t.key=Date.now();t.forceUpdate()}})))};t.onMouseEnter=function(e){t.setState({hover:!0});var n=t.props.onMouseEnter;null!=n&&n(e)};t.onMouseLeave=function(e){t.setState({hover:!1});var n=t.props.onMouseLeave;null!=n&&n(e)};return t}var n=t.prototype;n.componentWillUnmount=function(){var e;null===(e=this.cancelLoadImage)||void 0===e||e.call(this)};n.getSrc=function(e){void 0===e&&(e=this.props);var t=e,n=t.src,o=t.emojiId,r=t.emojiName,a=t.animated,i=t.shouldAnimate,u=t.isFocused,l=t.isInteracting,s=t.size,c=void 0===s?"default":s,f=this.state.hover;if(null!=n)return n;if(null!=o){var d=44
;switch(c){case"jumbo":d=96;break;case"reaction":d=32;break;default:d=44}return p.default.getEmojiURL({id:o,animated:u&&a&&(i||f||l),size:d})}return null!=r?v.default.getURL(r):void 0};n.render=function(){var e,t,n=this.props,o=n.emojiName,i=n.animated,u=n.className,l=n.size,s=void 0===l?"default":l,c=n.alt,f=(n.shouldAnimate,n.isFocused,n.emojiId),d=(n.autoplay,n.isInteracting,j(n,m)),p=this.getSrc();if(!p)return O("span",{className:(0,a.default)("emoji","emoji-text")},void 0,o);i&&(t={onMouseEnter:this.onMouseEnter,onMouseLeave:this.onMouseLeave});return r.createElement("img",_({},d,{key:this.key,src:p,alt:null!==(e=null!=c?c:o)&&void 0!==e?e:void 0,draggable:!1},t,{className:(0,a.default)("emoji",u,{jumboable:"jumbo"===s}),onError:this.onError},_({"data-type":"emoji"},f?{"data-id":f}:{"data-name":o})))};return t}(r.PureComponent);E.displayName="Emoji";E.defaultProps={isInteracting:!1};var k=u.default.connectStores([l.default,f.default,s.default,c.default],(function(e){
var t=e.autoplay;return{isFocused:__OVERLAY__?s.default.isInstanceFocused():f.default.isFocused(),autoplay:null==t?c.default.animateEmoji:t,reduceMotion:l.default.useReducedMotion}}))(function(e){if(null==window.IntersectionObserver)return function(t){return r.createElement(e,_({},t,{shouldAnimate:t.animated}))};var t=100,n=[],o=[],a=new window.IntersectionObserver((function(e){e.forEach((function(e){var r=o.find((function(t){return t[0]===e.target}));if(null!=r){var a=r[1];if(e.intersectionRatio>=.7){var i,u;if(-1!==n.indexOf(a)){0;return}var l=Math.abs(e.intersectionRect.bottom-Number(null===(i=e.rootBounds)||void 0===i?void 0:i.bottom))<Math.abs(e.intersectionRect.top-Number(null===(u=e.rootBounds)||void 0===u?void 0:u.top));l?n.unshift(a):n.push(a);a.forceUpdate();l&&n.length>t&&n[100].forceUpdate()}else{var s=n.indexOf(a);if(-1!==s){n.splice(s,1);a.forceUpdate();s<t&&n.length>=t&&n[99].forceUpdate()}}}else 0}))}),{threshold:.7});function u(e){var t=i.default.findDOMNode(e)
;if(t instanceof Element){o.push([t,e]);a.observe(t)}else 0}function l(e){var r=i.default.findDOMNode(e);a.unobserve(r);var u=o.findIndex((function(t){t[0];return t[1]===e}));if(-1!==u){o.splice(u,1);if(-1!==(u=n.indexOf(e))){n.splice(u,1);u<t&&n.length>=t&&n[99].forceUpdate()}}else 0}return function(o){M(a,o);function a(){return o.apply(this,arguments)||this}var i=a.prototype;i.shouldAutoplay=function(e){return e.animated&&e.autoplay};i.componentDidMount=function(){this.shouldAutoplay(this.props)&&u(this)};i.componentDidUpdate=function(e){var t=this.shouldAutoplay(e),n=this.shouldAutoplay(this.props);n!==t&&(n?u(this):l(this))};i.componentWillUnmount=function(){this.shouldAutoplay(this.props)&&l(this)};i.render=function(){var o=n.indexOf(this),a=this.props,i=a.autoplay,u=a.reduceMotion,l=j(a,y);return O(d.MessagesInteractionContext.Consumer,{},void 0,(function(n){return r.createElement(e,_({},l,{autoplay:i||!1,shouldAnimate:-1!==o&&o<t&&!n.disableAnimations&&!u}))}))};return a
}(r.Component)}(E));t.default=k},277334:(e,t,n)=>{Object.defineProperty(t,"__esModule",{value:!0});t.default=h;var o,r=function(e,t){if(!t&&e&&e.__esModule)return e;if(null===e||"object"!=typeof e&&"function"!=typeof e)return{default:e};var n=p(t);if(n&&n.has(e))return n.get(e);var o={},r=Object.defineProperty&&Object.getOwnPropertyDescriptor;for(var a in e)if("default"!==a&&Object.prototype.hasOwnProperty.call(e,a)){var i=r?Object.getOwnPropertyDescriptor(e,a):null;i&&(i.get||i.set)?Object.defineProperty(o,a,i):o[a]=e[a]}o.default=e;n&&n.set(e,o);return o}(n(667294)),a=d(n(16941)),i=d(n(776360)),u=n(647261),l=n(352333),s=n(196854),c=n(198756),f=d(n(87704));function d(e){return e&&e.__esModule?e:{default:e}}function p(e){if("function"!=typeof WeakMap)return null;var t=new WeakMap,n=new WeakMap;return(p=function(e){return e?n:t})(e)}function v(e,t,n,r){o||(o="function"==typeof Symbol&&Symbol.for&&Symbol.for("react.element")||60103);var a=e&&e.defaultProps,i=arguments.length-3
;t||0===i||(t={children:void 0});if(1===i)t.children=r;else if(i>1){for(var u=new Array(i),l=0;l<i;l++)u[l]=arguments[l+3];t.children=u}if(t&&a)for(var s in a)void 0===t[s]&&(t[s]=a[s]);else t||(t=a||{});return{$$typeof:o,type:e,key:void 0===n?null:""+n,ref:null,props:t,_owner:null}}function h(e){var t=e.guildScheduledEvent,n=e.channel,o=e.onClose,d=t.entity_type===c.GuildScheduledEventEntityTypes.EXTERNAL,p=r.useCallback((function(e){return(0,l.createEventLocationClickHandler)(t,o)(e)}),[t,o]),h=(0,s.getLocationDataForEvent)(t,n);if(null==h)return null;var y=h.IconComponent,m=h.locationName,b=r.createElement(r.Fragment,null,null!=y&&v(y,{width:20,height:20,className:f.default.channelIcon}),v(i.default,{color:i.default.Colors.HEADER_SECONDARY,size:i.default.Sizes.SIZE_14,className:f.default.locationText},void 0,(0,u.guildEventDetailsParser)(m,!0)));return v("div",{className:f.default.row},void 0,p?v(a.default,{className:d?f.default.externalLocation:f.default.channelLocation,onClick:p
},void 0,b):b)}h.displayName="EventDetailLocation"},430138:(e,t,n)=>{Object.defineProperty(t,"__esModule",{value:!0});t.MessagesInteractionContext=void 0;function o(e){if("function"!=typeof WeakMap)return null;var t=new WeakMap,n=new WeakMap;return(o=function(e){return e?n:t})(e)}var r=function(e,t){if(!t&&e&&e.__esModule)return e;if(null===e||"object"!=typeof e&&"function"!=typeof e)return{default:e};var n=o(t);if(n&&n.has(e))return n.get(e);var r={},a=Object.defineProperty&&Object.getOwnPropertyDescriptor;for(var i in e)if("default"!==i&&Object.prototype.hasOwnProperty.call(e,i)){var u=a?Object.getOwnPropertyDescriptor(e,i):null;u&&(u.get||u.set)?Object.defineProperty(r,i,u):r[i]=e[i]}r.default=e;n&&n.set(e,r);return r}(n(667294)).createContext({disableInteractions:!1,disableAnimations:!1});t.MessagesInteractionContext=r}}]);
//# sourceMappingURL=246d394f23555477fc24.js.map