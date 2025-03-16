import { Controller } from '@hotwired/stimulus';
export default class extends Controller {
    static values: {
        requestResultUrl: {
            type: StringConstructor;
            default: string;
        };
        requestOptionsUrl: {
            type: StringConstructor;
            default: string;
        };
        requestResultField: {
            type: StringConstructor;
            default: null;
        };
        requestSuccessRedirectUri: StringConstructor;
        creationResultUrl: {
            type: StringConstructor;
            default: string;
        };
        creationOptionsUrl: {
            type: StringConstructor;
            default: string;
        };
        creationResultField: {
            type: StringConstructor;
            default: null;
        };
        creationSuccessRedirectUri: StringConstructor;
        usernameField: {
            type: StringConstructor;
            default: string;
        };
        displayNameField: {
            type: StringConstructor;
            default: string;
        };
        attestationField: {
            type: StringConstructor;
            default: string;
        };
        userVerificationField: {
            type: StringConstructor;
            default: string;
        };
        residentKeyField: {
            type: StringConstructor;
            default: string;
        };
        authenticatorAttachmentField: {
            type: StringConstructor;
            default: string;
        };
        useBrowserAutofill: {
            type: BooleanConstructor;
            default: boolean;
        };
        requestHeaders: {
            type: ObjectConstructor;
            default: {
                'Content-Type': string;
                Accept: string;
                mode: string;
                credentials: string;
            };
        };
    };
    readonly requestResultUrlValue: string;
    readonly requestOptionsUrlValue: string;
    readonly requestResultFieldValue?: string;
    readonly requestSuccessRedirectUriValue?: string;
    readonly creationResultUrlValue: string;
    readonly creationOptionsUrlValue: string;
    readonly creationResultFieldValue?: string;
    readonly creationSuccessRedirectUriValue?: string;
    readonly usernameFieldValue: string;
    readonly displayNameFieldValue: string;
    readonly attestationFieldValue: string;
    readonly userVerificationFieldValue: string;
    readonly residentKeyFieldValue: string;
    readonly authenticatorAttachmentFieldValue: string;
    readonly useBrowserAutofillValue: boolean;
    readonly requestHeadersValue: object;
    connect: () => Promise<void>;
    signin(event: Event): Promise<void>;
    private _processSignin;
    signup(event: Event): Promise<void>;
    private _dispatchEvent;
    private _getData;
    private _getPublicKeyCredentialRequestOptions;
    private _getPublicKeyCredentialCreationOptions;
    private _getOptions;
    private _getAttestationResponse;
    private _getAssertionResponse;
    private _getResult;
    private _processExtensionsInput;
    private _processPrfInput;
    private _importPrfValues;
    private _processExtensionsOutput;
    private _processPrfOutput;
    private _exportPrfValues;
}
