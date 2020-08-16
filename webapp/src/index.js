import manifest from './manifest';

// Plugin class
export default class Plugin {
    // eslint-disable-next-line no-unused-vars
    initialize(registry, store) {
        // Configuration of hidden elements
        var HIDDEN_ELEMENTS = [
            '#invitePeople',
            '#invitePeople + .menu-divider',
            '#leaveTeam',
            '#leaveTeam + .menu-divider',
            '#about + .menu-divider',
            '#logout',
            '#generalButton',
            '#securityButton',
        ];
        var OPAQUE_ELEMENTS = ['#generalSettings'];

        // Add style sheet to document head
        $('<style>').
            attr('id', 'plugin-nextcloud-style').
            prop('type', 'text/css').
            html(
                HIDDEN_ELEMENTS.join(',') +
                ' { display: none !important; }' +
                OPAQUE_ELEMENTS.join(',') +
                ' { opacity: 0    !important; }',
            ).
            appendTo('head');
    }
}

window.registerPlugin(manifest.id, new Plugin());
