import re
import os
import sys
import idaapi
import traceback
# Make sure API is supported to enable use of other functionality in older versions.
# See http://www.hexblog.com/?p=886
#if idaapi.IDA_SDK_VERSION >= 670:
class ActionHandler(idaapi.action_handler_t):
    """A wrapper around `idaapi.action_handler_t`.
    The class simplifies the creation of UI actions in IDA >= 6.7.
    To create an action, simply create subclass and override the relevant fields
    and register it::
        class MyAction(ActionHandler):
            TEXT = "My Action"
            HOTKEY = "Alt+Z"
            def _activate(self, ctx):
                idaapi.msg("Activated!")
        MyAction.register()
    Additional Documentation:
        Introduction to `idaapi.action_handler_t`:
            http://www.hexblog.com/?p=886
        Return values for update (from the SDK):
            AST_ENABLE_ALWAYS     // enable action and do not call action_handler_t::update() anymore
            AST_ENABLE_FOR_IDB    // enable action for the current idb. Call action_handler_t::update() when a database is opened/closed
            AST_ENABLE_FOR_FORM   // enable action for the current form. Call action_handler_t::update() when a form gets/loses focus
            AST_ENABLE            // enable action - call action_handler_t::update() when anything changes
            AST_DISABLE_ALWAYS    // disable action and do not call action_handler_t::action() anymore
            AST_DISABLE_FOR_IDB   // analog of ::AST_ENABLE_FOR_IDB
            AST_DISABLE_FOR_FORM  // analog of ::AST_ENABLE_FOR_FORM
            AST_DISABLE           // analog of ::AST_ENABLE
    """
    NAME = None
    TEXT = "Default. Replace me!"
    HOTKEY = ""
    TOOLTIP = ""
    ICON = -1

    @classmethod
    def get_name(cls):
        """Return the name of the action.
        If a name has not been set (using the `Name` class variable), the
        function generates a name based on the class name and id.
        :return: action name
        :rtype: str
        """
        if cls.NAME is not None:
            return cls.NAME

        return "{}:{}".format(cls.__name__, id(cls))

    @classmethod
    def get_desc(cls):
        """Get a descriptor for this handler."""
        name = cls.get_name()
        text = cls.TEXT
        handler = cls()
        hotkey = cls.HOTKEY
        tooltip = cls.TOOLTIP
        icon = cls.ICON
        action_desc = idaapi.action_desc_t(
            name,
            text,
            handler,
            hotkey,
            tooltip,
            icon,
        )
        return action_desc

    @classmethod
    def register(cls):
        """Register the action.
        Each action MUST be registered before it can be used. To remove the action
        use the `unregister` method.
        """
        action_desc = cls.get_desc()

        return idaapi.register_action(action_desc)

    @classmethod
    def unregister(cls):
        """Unregister the action.
        After unregistering the class cannot be used.
        """
        idaapi.unregister_action(cls.get_name())

    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        try:
            self._activate(ctx)
            return 1
        except:
            trace = traceback.format_exc()
            idaapi.msg("Action {!r} failed to activate. Traceback:\n{}".format(self.get_name(), trace))
            return 0

    def update(self, ctx):
        """Update the action.
        Optionally override this function.
        See IDA-SDK for more information.
        """
        return idaapi.AST_ENABLE_ALWAYS

    def _activate(self, ctx):
        """Activate the action.
        This function contains the action code itself. You MUST implement
        it in your class for the action to work.
        Args:
            ctx: The action context passed from IDA.
        """
        raise NotImplementedError()
