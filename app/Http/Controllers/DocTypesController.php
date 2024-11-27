<?php

namespace App\Http\Controllers;

use App\Models\DocumentTypes;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;

class DocTypesController extends Controller
{
    public function index()
    {
        try {

            // Obtener todos los tipos de documentos
            $doctypes = DocumentTypes::all();

            // Devolver una respuesta JSON con los tipos de documentos
            return response()->json([
                'status' => true,
                'data' => $doctypes
            ],200);
        } catch (\Throwable $th) {

            // Manejar la excepción y devolver un mensaje de error
            return response()->json([
              'status' => false,
              'message' => "Error in index, not found elements"
            ],500);
        }
    }
    public function store(Request $request)
    {

        // Reglas de validación para los datos de los tipos de documentos
        $rules = [
            'doc_typ_name' => 'required|string|min:1|max:255|unique:document_types|regex:/^[A-ZÑÁÉÍÓÚÜ\s]+$/',
            'use_id' =>'required|integer|exists:users'
        ];

        // Realizar la validación de los datos recibidos
        $validator = Validator::make($request->input(), $rules);

        // Si la validación falla, devolver los errores
        if ($validator->fails()) {
            return response()->json([
               'status' => False,
               'message' => $validator->errors()->all()
            ]);
        }else{

            // Crear un nuevo tipo de documento
            $doctypes = new DocumentTypes($request->input());
            $doctypes->save();

            // Disparar un nuevo registro
            Controller::NewRegisterTrigger("Se creo un registro en la tabla DocTypes: $request->doc_typ_name ",3,$request->use_id);

            // Devolver una respuesta JSON de éxito
            return response()->json([
               'status' => True,
               'message' => "The type document: ".$doctypes->doc_typ_name." has been created."
            ],200);
        }
    }
    public function show($id)
    {

        // Buscar un tipo de documento por su ID
        $docTypes = DocumentTypes::find($id);

        // Si el tipo de documento no se encuentra, devolver un mensaje de error
        if($docTypes == null){
            return response()->json([
                'status' => False,
                'data' => ['message' => 'The document typ requested not found'],
            ],400);
        }else{

            // Devolver el tipo de documento encontrado
            return response()->json([
                'status' => true,
                'data' => $docTypes
            ]);
        }
    }
    public function update(Request $request, $id)
    {

        // Buscar un tipo de documento por su ID
        $docTypes = DocumentTypes::find($id);

        // Si el tipo de documento no se encuentra, devolver un mensaje de error
        if($docTypes == null){
            return response()->json([
                'status' => False,
                'data' => ['message' => 'The document typ requested not found'],
            ],400);
        }else{

            // Reglas de validación para actualizar los datos del tipo de documento
            $rules = [
                'doc_typ_name' => 'required|string|min:1|max:255|regex:/^[A-ZÑÁÉÍÓÚÜ\s]+$/',
                'use_id' =>'required|integer|exists:users'
            ];

            // Realizar la validación de los datos recibidos
            $validator = Validator::make($request->input(), $rules);

            // Validar que no exista otro tipo de documento con el mismo nombre
            $validate = Controller::validate_exists($request->doc_typ_name, 'document_types', 'doc_typ_name', 'doc_typ_id', $id);

            // Si la validación falla o ya existe otro tipo de documento con el mismo nombre, devolver los errores
            if ($validator->fails() || $validate == 0) {
                $msg = ($validate == 0) ? "value tried to register, it is already registered." : $validator->errors()->all();
                return response()->json([
                  'status' => False,
                  'message' => $msg
                ]);
            }else{

                // Actualizar los datos del tipo de documento
                $docTypes->doc_typ_name = $request->doc_typ_name;
                $docTypes->save();

                // Disparar un nuevo registro
                Controller::NewRegisterTrigger("Se realizo una Edicion de datos en la tabla DocTypes del dato: $id con el dato: $request->doc_typ_name",1,$request->use_id);

                // Devolver una respuesta JSON de éxito
                return response()->json([
                  'status' => True,
                  'message' => "The type document: ".$docTypes->doc_typ_name." has been update."
                ],200);
            }
        }
    }
    public function destroy(DocumentTypes $DocumentTypes)
    {

        // Devolver un mensaje indicando que esta función no está disponible
        return response()->json([
            'status' => true,
            'message' => "FUNCTION NOT AVAILABLE"
        ],400);
    }
}
