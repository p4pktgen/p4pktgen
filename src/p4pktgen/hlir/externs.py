import os
import imp
import inspect

from p4pktgen.config import Config


class Externs(object):
    def __init__(self):
        self.extern_backends = {}

    @staticmethod
    def load_external_module(src_path):
        module_name = os.path.basename(src_path)
        return imp.load_source(module_name, src_path)

    def load_external_class(self, src_path):
        external_module = self.load_external_module(src_path)
        class_list = inspect.getmembers(external_module, inspect.isclass)
        assert len(class_list) == 1, "Expected exactly one class in {}, got {}".format(
            external_module.__name__, class_list
        )
        return class_list[0][1]

    def load_extern_instance(self, src_path, args):
        """
        Loads extern backend from python source file outside of p4pktgen.
        Source file must contain exactly one class.  The class should have
        constructor and methods that accept arguments in the z3 equivalents to the
        p4 arguments.  Typically this will mean BitVecs of the correct size.
        """
        extern_class = self.load_external_class(src_path)
        return extern_class(*args)

    def parse_instance_attribute_values(self, extern_instance):
        args = []
        for attr_val in extern_instance.attribute_values:
            # TODO: Support str and expr arguments as necessary
            assert attr_val.type == 'hexstr'
            args.append(int(attr_val.value, 16))
        return args

    def load_instances(self, extern_instances):
        extern_definitions = Config().get_extern_definitions()
        for name, instance in extern_instances.iteritems():
            assert name in extern_definitions, \
                "Extern definition not provided for '{}'".format(name)
            src_file = extern_definitions[name]
            args = self.parse_instance_attribute_values(instance)
            self.extern_backends[name] = self.load_extern_instance(src_file, args)

    def get_func(self, instance, function_name):
        backend = self.extern_backends[instance.name]
        assert hasattr(backend, function_name),\
            'Extern definition provided for {} does not implement {}'.format(
                instance.name, function_name)
        return getattr(backend, function_name)
